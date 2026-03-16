package main

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/ebpf/btf"
)

type patch func(*btf.Struct) error

func modify(fn func(*btf.Member) error, members ...string) patch {
	return func(s *btf.Struct) error {
		want := make(map[string]bool)
		for _, name := range members {
			want[name] = true
		}

		for i, m := range s.Members {
			if want[m.Name] {
				if err := fn(&s.Members[i]); err != nil {
					return err
				}
				delete(want, m.Name)
			}
		}

		if len(want) == 0 {
			return nil
		}

		var missing []string
		for name := range want {
			missing = append(missing, name)
		}
		sort.Strings(missing)

		return fmt.Errorf("missing members: %v", strings.Join(missing, ", "))
	}
}

func modifyNth(fn func(*btf.Member) error, indices ...int) patch {
	return func(s *btf.Struct) error {
		for _, i := range indices {
			if i >= len(s.Members) {
				return fmt.Errorf("index %d is out of bounds", i)
			}

			if err := fn(&s.Members[i]); err != nil {
				return fmt.Errorf("member #%d: %w", i, err)
			}
		}
		return nil
	}
}

func replace(t btf.Type, members ...string) patch {
	return modify(func(m *btf.Member) error {
		m.Type = t
		return nil
	}, members...)
}

func choose(member int, name string) patch {
	return modifyNth(func(m *btf.Member) error {
		union, ok := m.Type.(*btf.Union)
		if !ok {
			return fmt.Errorf("member %d is %s, not a union", member, m.Type)
		}

		for _, um := range union.Members {
			if um.Name == name {
				m.Name = um.Name
				m.Type = um.Type
				return nil
			}
		}

		return fmt.Errorf("%s has no member %q", union, name)
	}, member)
}

func chooseNth(member int, n int) patch {
	return modifyNth(func(m *btf.Member) error {
		union, ok := m.Type.(*btf.Union)
		if !ok {
			return fmt.Errorf("member %d is %s, not a union", member, m.Type)
		}

		if n >= len(union.Members) {
			return fmt.Errorf("member %d is out of bounds", n)
		}

		um := union.Members[n]
		m.Name = um.Name
		m.Type = um.Type
		return nil
	}, member)
}

func flattenAnon(s *btf.Struct) error {
	for i := range s.Members {
		m := &s.Members[i]

		if m.Type.TypeName() != "" {
			continue
		}

		var newMembers []btf.Member
		switch cs := m.Type.(type) {
		case *btf.Struct:
			for j := range cs.Members {
				cs.Members[j].Offset += m.Offset
			}
			newMembers = cs.Members

		case *btf.Union:
			cs.Members[0].Offset += m.Offset
			newMembers = []btf.Member{cs.Members[0]}

		default:
			continue
		}

		s.Members = slices.Replace(s.Members, i, i+1, newMembers...)
	}

	return nil
}

func truncateAfter(name string) patch {
	return func(s *btf.Struct) error {
		for i, m := range s.Members {
			if m.Name != name {
				continue
			}

			size, err := btf.Sizeof(m.Type)
			if err != nil {
				return err
			}

			s.Members = s.Members[:i+1]
			s.Size = m.Offset.Bytes() + uint32(size)
			return nil
		}

		return fmt.Errorf("no member %q", name)
	}
}

func rename(from, to string) patch {
	return func(s *btf.Struct) error {
		for i, m := range s.Members {
			if m.Name == from {
				s.Members[i].Name = to
				return nil
			}
		}
		return fmt.Errorf("no member named %q", from)
	}
}

func renameNth(idx int, to string) patch {
	return func(s *btf.Struct) error {
		if idx >= len(s.Members) {
			return fmt.Errorf("index %d is out of bounds", idx)
		}
		s.Members[idx].Name = to
		return nil
	}
}

func name(member int, name string) patch {
	return modifyNth(func(m *btf.Member) error {
		if m.Name != "" {
			return fmt.Errorf("member already has name %q", m.Name)
		}

		m.Name = name
		return nil
	}, member)
}

func replaceWithBytes(members ...string) patch {
	return modify(func(m *btf.Member) error {
		if m.BitfieldSize != 0 {
			return errors.New("replaceWithBytes: member is a bitfield")
		}

		size, err := btf.Sizeof(m.Type)
		if err != nil {
			return fmt.Errorf("replaceWithBytes: size of %s: %w", m.Type, err)
		}

		m.Type = &btf.Array{
			Type:   &btf.Int{Size: 1},
			Nelems: uint32(size),
		}

		return nil
	}, members...)
}

func remove(member string) patch {
	return func(s *btf.Struct) error {
		for i, m := range s.Members {
			if m.Name == member {
				s.Members = slices.Delete(s.Members, i, i+1)
				return nil
			}
		}
		return fmt.Errorf("member %q not found", member)
	}
}
