package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// The mouse, as in btop: what is drawn is where it is clicked. While rendering, clickable parts are wrapped in
// zero-width markers (zone); View finds them in the finished frame, keeps their rectangles and removes the markers,
// so the hit areas come from the very layout on screen. A click runs the zone's handler with the column it fell on
// within the zone; the wheel scrolls what is under it.

const (
	zoneOpen  = "\x1b]8999;" // zoneOpen + id + "\a" ... zoneClose: never sent to the terminal
	zoneClose = "\x1b]8998\a"
)

// hitZone: a clickable span of one screen line.
type hitZone struct {
	id     string
	y      int
	x0, x1 int // columns [x0, x1)
}

// zone: s, clickable; h runs on a click with the column within it.
func (m *Model) zone(id, s string, h func(dx int) tea.Cmd) string {
	if m.handlers == nil {
		m.handlers = map[string]func(int) tea.Cmd{}
	}
	m.handlers[id] = h
	return zoneOpen + id + "\a" + s + zoneClose
}

// zoneKey: s, clickable as pressing key.
func (m *Model) zoneKey(key, s string) string {
	m.zoneSeq++ // ids stay ASCII: the escape parser must not meet UTF-8 in them
	return m.zone(fmt.Sprintf("key:%d", m.zoneSeq), s, func(int) tea.Cmd { return m.press(key) })
}

// scanZones: the zones of the frame's lines; the lines without their markers.
func (m *Model) scanZones(lines []string) []string {
	m.zones = m.zones[:0]
	for y, l := range lines {
		if !strings.Contains(l, zoneOpen) {
			continue
		}
		var b strings.Builder
		var open []hitZone
		x := 0
		for i := 0; i < len(l); {
			switch {
			case strings.HasPrefix(l[i:], zoneOpen):
				end := strings.IndexByte(l[i:], '\a')
				if end < 0 {
					i = len(l)
					continue
				}
				open = append(open, hitZone{id: l[i+len(zoneOpen) : i+end], y: y, x0: x})
				i += end + 1
			case strings.HasPrefix(l[i:], zoneClose):
				if n := len(open); n > 0 {
					z := open[n-1]
					z.x1 = x
					m.zones = append(m.zones, z)
					open = open[:n-1]
				}
				i += len(zoneClose)
			case l[i] == '\x1b': // another escape sequence: no width
				n := escLen(l[i:])
				b.WriteString(l[i : i+n])
				i += n
			default:
				r, n := utf8.DecodeRuneInString(l[i:])
				b.WriteString(l[i : i+n])
				x += ansi.StringWidth(string(r))
				i += n
			}
		}
		for _, z := range open { // cut off at the end of the line
			z.x1 = x
			m.zones = append(m.zones, z)
		}
		lines[y] = b.String()
	}
	return lines
}

// escLen: the length of the escape sequence s starts with (CSI, OSC; else two bytes).
func escLen(s string) int {
	if len(s) < 2 {
		return len(s)
	}
	switch s[1] {
	case '[':
		for i := 2; i < len(s); i++ {
			if s[i] >= 0x40 && s[i] <= 0x7e {
				return i + 1
			}
		}
		return len(s)
	case ']':
		for i := 2; i < len(s); i++ {
			if s[i] == '\a' {
				return i + 1
			}
			if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
		}
		return len(s)
	}
	return 2
}

// zoneAt: the innermost zone at a cell.
func (m *Model) zoneAt(x, y int) (hitZone, bool) {
	var best hitZone
	found := false
	for _, z := range m.zones {
		if z.y == y && x >= z.x0 && x < z.x1 && (!found || z.x1-z.x0 < best.x1-best.x0) {
			best, found = z, true
		}
	}
	return best, found
}

// mouse: a click on a zone; the wheel as up/down (or the details pane's scroll); a click outside an open list
// closes it.
func (m *Model) mouse(msg tea.MouseMsg) tea.Cmd {
	if m.set.NoMouse || msg.Action != tea.MouseActionPress {
		return nil
	}
	z, ok := m.zoneAt(msg.X, msg.Y)
	inPane := false // over the details pane (its lines hold other zones too)
	for _, p := range m.zones {
		inPane = inPane || p.y == msg.Y && msg.X >= p.x0 && msg.X < p.x1 && strings.HasPrefix(p.id, "detpane")
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp, tea.MouseButtonWheelDown:
		d := map[tea.MouseButton]int{tea.MouseButtonWheelUp: -1, tea.MouseButtonWheelDown: 1}[msg.Button]
		if inPane {
			m.detOff = max(m.detOff+3*d, 0)
			return nil
		}
		k := map[int]string{-1: "up", 1: "down"}[d]
		var cmds []tea.Cmd
		for range 3 {
			cmds = append(cmds, m.press(k))
		}
		return tea.Batch(cmds...)
	case tea.MouseButtonLeft:
	default:
		return nil
	}
	if m.menu != nil && (!ok || !strings.HasPrefix(z.id, "menu")) {
		m.menu = nil // a click outside the list closes it
		return nil
	}
	if w := m.setup; w != nil && w.pick != nil && (!ok || !strings.HasPrefix(z.id, "pick")) {
		w.pick = nil
		return nil
	}
	if !ok {
		return nil
	}
	h := m.handlers[z.id]
	if h == nil {
		return nil
	}
	return h(msg.X - z.x0)
}

// press: what pressing key does (a click on a key hint, a tab, a button).
func (m *Model) press(key string) tea.Cmd {
	return m.update(keyMsg(key))
}

// keyMsg: a key by its name as the hints write it.
func keyMsg(key string) tea.KeyMsg {
	named := map[string]tea.KeyType{"enter": tea.KeyEnter, "⏎": tea.KeyEnter, "esc": tea.KeyEsc, "tab": tea.KeyTab,
		"shift+tab": tea.KeyShiftTab, "up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight,
		"→←": tea.KeyRight, "home": tea.KeyHome, "end": tea.KeyEnd, "pgup": tea.KeyPgUp, "pgdown": tea.KeyPgDown,
		"backspace": tea.KeyBackspace, "ctrl+s": tea.KeyCtrlS, "ctrl+o": tea.KeyCtrlO, "ctrl+d": tea.KeyCtrlD,
		"ctrl+k": tea.KeyCtrlK, "ctrl+c": tea.KeyCtrlC}
	switch key {
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")}
	case "[ ]":
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("]")}
	}
	if t, ok := named[key]; ok {
		return tea.KeyMsg{Type: t}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
}

// rowClick: a click on a row of a list: the cursor there; on the row it already is on, what enter does. In the tree
// the check mark selects, the caret opens and closes.
func (m *Model) rowClick(i, dx int) tea.Cmd {
	was := m.cur[m.view] == i
	m.cur[m.view] = i
	if m.isTree() && m.host == "" {
		rows := m.treeRows()
		if i >= len(rows) {
			return nil
		}
		n := rows[i].n
		m.curID, m.cmdCur = n.ID, 0
		switch {
		case dx <= 1: // ○ ●
			m.toggleSel(n)
			return nil
		case dx <= 3 && len(n.Kids) > 0: // ▸ ▾
			if m.opened[n.ID] {
				delete(m.opened, n.ID)
			} else {
				m.opened[n.ID] = true
			}
			return nil
		}
	}
	if was {
		return m.press("enter")
	}
	return nil
}

// mouseCmd: mouse reporting on or off, as set (o).
func (m *Model) mouseCmd() tea.Cmd {
	if m.set.NoMouse {
		return tea.DisableMouse
	}
	return tea.EnableMouseCellMotion
}
