// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The gadget authors

//go:build wasip1

package main

import (
	"fmt"
	"strconv"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"

	"github.com/mqasimsarfraz/snapshot_mapped_files/internal/snapshot"
)

type fieldSpec struct {
	name string
	kind api.FieldKind
	tag  string
}

var outputFields = []fieldSpec{
	{"mntns_id", api.Kind_Uint64, "type:gadget_mntns_id"},
	{"pid", api.Kind_Uint32, "type:gadget_pid"},
	{"process_start_ns", api.Kind_Uint64, ""},
	{"comm", api.Kind_String, ""},
	{"fname", api.Kind_String, ""},
	{"dev_major", api.Kind_Uint32, ""},
	{"dev_minor", api.Kind_Uint32, ""},
	{"inode", api.Kind_Uint64, ""},
	{"permissions", api.Kind_String, ""},
	{"mapping_count", api.Kind_Uint64, ""},
	{"mapped_bytes", api.Kind_Uint64, ""},
	{"path_variants", api.Kind_Uint32, ""},
	{"deleted", api.Kind_Bool, ""},
	{"path_error", api.Kind_Int32, ""},
}

func initGadget() error {
	raw, err := api.GetDataSource("mappings")
	if err != nil {
		return err
	}
	input := make(map[string]api.Field)
	for _, name := range []string{
		"mntns_id", "pid", "process_start_ns", "comm", "fname", "dev_major",
		"dev_minor", "inode", "flags", "start", "end", "offset_pages", "deleted", "path_error",
	} {
		input[name], err = raw.GetField(name)
		if err != nil {
			return err
		}
	}
	out, err := api.NewDataSource("mapped_files", api.DataSourceTypeArray)
	if err != nil {
		return err
	}
	output := make(map[string]api.Field)
	for _, spec := range outputFields {
		f, err := out.AddField(spec.name, spec.kind)
		if err != nil {
			return err
		}
		if spec.tag != "" {
			if err := f.AddTag(spec.tag); err != nil {
				return fmt.Errorf("tagging %s: %w", spec.name, err)
			}
		}
		output[spec.name] = f
	}
	if err := raw.Unreference(); err != nil {
		return err
	}
	return raw.SubscribeArray(func(_ api.DataSource, data api.DataArray) error {
		if err := emitSnapshot(data, input, out, output); err != nil {
			api.Errorf("processing mapped-file snapshot: %s", err)
			return err
		}
		return nil
	}, 0)
}

func emitSnapshot(data api.DataArray, input map[string]api.Field, out api.DataSource, output map[string]api.Field) error {
	value, err := api.GetParamValue("shared-libs-only", 8)
	if err != nil {
		return fmt.Errorf("reading shared-libs-only: %w", err)
	}
	libsOnly, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("parsing shared-libs-only: %w", err)
	}
	s := snapshot.New()
	for i := 0; i < data.Len(); i++ {
		m, err := readMapping(input, data.Get(i))
		if err != nil {
			return err
		}
		if err := s.Add(m); err != nil {
			return err
		}
	}
	packet, err := out.NewPacketArray()
	if err != nil {
		return err
	}
	for _, f := range s.Files {
		if libsOnly && !f.Library {
			continue
		}
		d := api.DataArray(packet).New()
		if err := writeFile(output, d, f); err != nil {
			if releaseErr := out.Release(api.Packet(packet)); releaseErr != nil {
				api.Errorf("releasing mapped-file snapshot: %s", releaseErr)
			}
			return err
		}
		if err := api.DataArray(packet).Append(d); err != nil {
			if releaseErr := out.Release(api.Packet(packet)); releaseErr != nil {
				api.Errorf("releasing mapped-file snapshot: %s", releaseErr)
			}
			return err
		}
	}
	return out.EmitAndRelease(api.Packet(packet))
}

type fieldReader struct {
	fields map[string]api.Field
	data   api.Data
	err    error
}

func (r *fieldReader) u64(name string) uint64 {
	v, err := r.fields[name].Uint64(r.data)
	r.check(name, err)
	return v
}

func (r *fieldReader) u32(name string) uint32 {
	v, err := r.fields[name].Uint32(r.data)
	r.check(name, err)
	return v
}

func (r *fieldReader) str(name string, size uint32) string {
	v, err := r.fields[name].String(r.data, size)
	r.check(name, err)
	return v
}

func (r *fieldReader) check(name string, err error) {
	if err != nil && r.err == nil {
		r.err = fmt.Errorf("reading %s: %w", name, err)
	}
}

func readMapping(fields map[string]api.Field, data api.Data) (snapshot.Mapping, error) {
	r := &fieldReader{fields: fields, data: data}
	m := snapshot.Mapping{
		FileKey: snapshot.FileKey{
			Mntns: r.u64("mntns_id"), PID: r.u32("pid"),
			ProcessStart: r.u64("process_start_ns"), Inode: r.u64("inode"),
			Major: r.u32("dev_major"), Minor: r.u32("dev_minor"), Flags: r.u32("flags"),
		},
		Start: r.u64("start"), End: r.u64("end"), OffsetPages: r.u64("offset_pages"),
		Comm: r.str("comm", 16), Fname: r.str("fname", 4096),
	}
	var err error
	m.Deleted, err = fields["deleted"].Bool(data)
	r.check("deleted", err)
	m.PathError, err = fields["path_error"].Int32(data)
	r.check("path_error", err)
	return m, r.err
}

func writeFile(fields map[string]api.Field, data api.Data, f snapshot.File) error {
	for _, v := range []struct {
		name  string
		value uint64
	}{
		{"mntns_id", f.Mntns}, {"process_start_ns", f.ProcessStart},
		{"inode", f.Inode}, {"mapping_count", f.MappingCount}, {"mapped_bytes", f.MappedBytes},
	} {
		if err := fields[v.name].SetUint64(data, v.value); err != nil {
			return fmt.Errorf("writing %s: %w", v.name, err)
		}
	}
	for _, v := range []struct {
		name  string
		value uint32
	}{
		{"pid", f.PID}, {"dev_major", f.Major}, {"dev_minor", f.Minor},
		{"path_variants", uint32(len(f.PathVariants))},
	} {
		if err := fields[v.name].SetUint32(data, v.value); err != nil {
			return fmt.Errorf("writing %s: %w", v.name, err)
		}
	}
	for _, v := range []struct{ name, value string }{
		{"comm", f.Comm}, {"fname", f.Fname}, {"permissions", snapshot.Permissions(f.Flags)},
	} {
		if err := fields[v.name].SetString(data, v.value); err != nil {
			return fmt.Errorf("writing %s: %w", v.name, err)
		}
	}
	if err := fields["deleted"].SetBool(data, f.Deleted); err != nil {
		return fmt.Errorf("writing deleted: %w", err)
	}
	if err := fields["path_error"].SetInt32(data, f.PathError); err != nil {
		return fmt.Errorf("writing path_error: %w", err)
	}
	return nil
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	if err := initGadget(); err != nil {
		api.Errorf("initializing mapped files: %s", err)
		return 1
	}
	return 0
}

func main() {}
