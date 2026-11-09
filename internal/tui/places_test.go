package tui

import (
	"encoding/json"
	"testing"
)

// TestPlaces: three places; Servers shows lenses (w, or a click on the switch), drawn by the views that showed them
// while the server has no lenses; History lists the runs, what changed and the scans; ToDo's accepted risks.
func TestPlaces(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(160, 40)
	h.key("1")
	h.has(" 1 Servers ", "2 ToDo", "3 History", "show  priorities  logins  network  health  w", "group by  server")
	h.key("w")
	h.has("Access(acme/production)", "show  priorities  logins  network  health  w")
	h.click(" network ")
	h.has("Network(acme/production)")
	h.key("w", "w")
	if h.m.lens != "priorities" || h.m.view != vServers {
		t.Fatal(h.m.lens, h.m.view)
	}
	h.key(":", "h", "e", "a", "l", "t", "h", "enter")
	h.has("Health(acme/production)")
	h.key("2", "1") // the lens stays
	h.has("Health(acme/production)")
	// History: runs; n what changed, j the scans, esc back
	h.key("3")
	h.has("History(acme/production)[5]", "n changes", "S scans")
	h.key("n")
	h.has("Changes(acme/production)")
	h.key("esc")
	h.has("History(acme/production)")
	h.key("S")
	h.has("Scans[")
	h.key("esc", "2", "f")
	// ToDo: the accepted risks
	for h.m.menuItems(h.m.menu)[h.m.menu.cur].id != "accepted" {
		h.key("down")
	}
	h.key("space", "esc")
	h.has("ToDo(acme/production)", "accepted risks", "UNTIL", "WHO", "REASON", "no internet")
}

// TestLens: a lens the server draws: its columns as the table rules lay them out, colour where it needs
// attention; enter opens the host card.
func TestLens(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 30)
	var d lensResp
	must(t, json.Unmarshal([]byte(`{"lenses":[{"id":"priorities","title":"priorities"},{"id":"disks","title":"disks"}],
		"lens":{"id":"disks","columns":[{"key":"use","title":"used","align":"right","unit":"%"},{"key":"mount","title":"mount"}]},
		"rows":[{"host":"web-01","cells":{"use":{"v":96,"level":"bad"},"mount":{"s":"/"}}},
		        {"host":"dead-01","state":"failed","cells":{}}]}`), &d))
	h.m.lensAPI = true
	h.key("1")
	h.m.lens = "disks"
	h.m.lensData, h.m.lensFor = &d, h.m.lensKey()
	h.m.setLens("disks")
	h.has("Servers(acme/production)[2]", "SERVER", "USED %", "MOUNT", "web-01", "96", "✗ dead-01", "show  priorities  disks  w")
	h.key("enter")
	h.has("Host(web-01)")
}
