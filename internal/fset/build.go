package fset

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/maphash"
	"slices"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Builder makes a Set, keeping each distinct part once.
type Builder struct {
	set   *Set
	cves  map[key]*CVE // by the part's JSON (hashed: the JSON itself would be as large as the parts)
	rests map[key]*Rest
	units map[Unit]*Unit
	strs  map[string]string // one copy of each string of the parts
	ptrs  map[string]*string
}

// NewBuilder: a builder of an empty set.
func NewBuilder() *Builder {
	return &Builder{set: &Set{}, cves: map[key]*CVE{}, rests: map[key]*Rest{}, units: map[Unit]*Unit{},
		strs: map[string]string{}, ptrs: map[string]*string{}}
}

// key: a part's JSON hashed to 128 bits (two seeds), so equal parts meet and different ones don't, as near
// certainly as matters (a million parts: about 2^-88 for any two to collide).
type key [2]uint64

var seeds = [2]maphash.Seed{maphash.MakeSeed(), maphash.MakeSeed()}

func keyOf(b []byte) key { return key{maphash.Bytes(seeds[0], b), maphash.Bytes(seeds[1], b)} }

func (b *Builder) intern(ps []*string) {
	for _, p := range ps {
		if s, ok := b.strs[*p]; ok {
			*p = s
		} else {
			b.strs[*p] = *p
		}
	}
}

// ptr: one pointer per distinct priority or due date.
func (b *Builder) ptr(p *string) *string {
	if p == nil {
		return nil
	}
	if q, ok := b.ptrs[*p]; ok {
		return q
	}
	b.intern([]*string{p})
	b.ptrs[*p] = p
	return p
}

// Of: the set of findings.
func Of(findings []finding.Finding) *Set {
	b := NewBuilder()
	for i := range findings {
		if err := b.Add(&findings[i]); err != nil {
			panic(err) // only unencodable Args (not from JSON) get here
		}
	}
	return b.Set()
}

// Grow makes room for n more items (a caller that knows how many will come saves the slack of growing).
func (b *Builder) Grow(n int) { b.set.Items = slices.Grow(b.set.Items, n) }

// Set: what was added.
func (b *Builder) Set() *Set { return b.set }

// Add adds a finding (f is not kept).
func (b *Builder) Add(f *finding.Finding) error {
	c, r := split(f)
	key, kind := report.FixKey(f)
	r.U = &Unit{key, kind}
	ck, err := json.Marshal(&c)
	if err != nil {
		return err
	}
	rk, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	b.set.Items = append(b.set.Items, Item{Rest: b.rest(keyOf(rk), &r), C: b.cve(keyOf(ck), &c)})
	return nil
}

func (b *Builder) cve(k key, c *CVE) *CVE {
	if p, ok := b.cves[k]; ok {
		return p
	}
	p := new(CVE)
	*p = *c
	b.intern(p.strs())
	p.Idx = int32(len(b.set.CVEs))
	b.cves[k] = p
	b.set.CVEs = append(b.set.CVEs, p)
	return p
}

func (b *Builder) rest(k key, r *Rest) *Rest {
	if p, ok := b.rests[k]; ok {
		return p
	}
	p := new(Rest)
	*p = *r
	b.intern(p.strs())
	p.Priority, p.Due, p.U = b.ptr(p.Priority), b.ptr(p.Due), b.unit(*p.U)
	p.Idx = int32(len(b.set.Rests))
	p.derive()
	b.rests[k] = p
	b.set.Rests = append(b.set.Rests, p)
	return p
}

func (b *Builder) unit(u Unit) *Unit {
	if p, ok := b.units[u]; ok {
		return p
	}
	p := &u
	b.units[u] = p
	b.set.Units = append(b.set.Units, p)
	return p
}

// Encode: the set as stored: parts (the CVE parts, then the rests: a count, then each one's length and JSON, as
// uvarints), items (two little-endian uint32 indexes each: CVE, rest) and the CVE parts' descriptions (by index;
// the parts leave them out).
func (s *Set) Encode() (parts, items []byte, descs []string, err error) {
	parts = binary.AppendUvarint(parts, uint64(len(s.CVEs)))
	ds, err := Descriptions(s.CVEs)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, c := range s.CVEs {
		b, err := json.Marshal(c)
		if err != nil {
			return nil, nil, nil, err
		}
		parts = append(binary.AppendUvarint(parts, uint64(len(b))), b...)
	}
	parts = binary.AppendUvarint(parts, uint64(len(s.Rests)))
	for _, r := range s.Rests {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, nil, nil, err
		}
		parts = append(binary.AppendUvarint(parts, uint64(len(b))), b...)
	}
	items = make([]byte, 0, 8*len(s.Items))
	for _, it := range s.Items {
		items = binary.LittleEndian.AppendUint32(items, uint32(it.C.Idx))
		items = binary.LittleEndian.AppendUint32(items, uint32(it.Idx))
	}
	return parts, items, ds, nil
}

// chunks: the JSON texts of one list of parts at the start of b, and what follows.
func chunks(b []byte) ([][]byte, []byte, error) {
	n, w := binary.Uvarint(b)
	if w <= 0 || n > uint64(len(b)) {
		return nil, nil, fmt.Errorf("parts: a bad count")
	}
	b = b[w:]
	out := make([][]byte, n)
	for i := range out {
		l, w := binary.Uvarint(b)
		if w <= 0 || l > uint64(len(b)-w) {
			return nil, nil, fmt.Errorf("parts: part %d cut", i)
		}
		out[i], b = b[w:w+int(l)], b[w+int(l):]
	}
	return out, b, nil
}

// AddEncoded adds a stored set (Encode) after what is there, sharing the parts both have. Its descriptions are
// left out: lazy fetches them (refs ds << 32 | the CVE's index), or with lazy nil they stay empty.
func (b *Builder) AddEncoded(parts, items []byte, lazy *Lazy, ds int64) error {
	cvesJSON, rest, err := chunks(parts)
	if err != nil {
		return err
	}
	restsJSON, rest, err := chunks(rest)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("parts: %d bytes after the parts", len(rest))
	}
	cves := make([]*CVE, len(cvesJSON))
	for i, raw := range cvesJSON {
		k := keyOf(raw)
		if p, ok := b.cves[k]; ok {
			cves[i] = p
			continue
		}
		var c CVE
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		if c.DescHash != 0 && lazy != nil {
			c.ref, c.lazy = ds<<32|int64(i), lazy
		}
		cves[i] = b.cve(k, &c)
	}
	rests := make([]*Rest, len(restsJSON))
	for i, raw := range restsJSON {
		k := keyOf(raw)
		if p, ok := b.rests[k]; ok {
			rests[i] = p
			continue
		}
		var r Rest
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		rests[i] = b.rest(k, &r)
	}
	if len(items)%8 != 0 {
		return fmt.Errorf("items: %d bytes", len(items))
	}
	n := len(items) / 8
	b.set.Items = slices.Grow(b.set.Items, n)
	for i := range n {
		c, r := binary.LittleEndian.Uint32(items[8*i:]), binary.LittleEndian.Uint32(items[8*i+4:])
		if int(c) >= len(cves) || int(r) >= len(rests) {
			return fmt.Errorf("item %d out of range", i)
		}
		b.set.Items = append(b.set.Items, Item{Rest: rests[r], C: cves[c]})
	}
	return nil
}
