package names

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func readRaw(t *testing.T, r *Registry) map[string]Entry {
	t.Helper()
	raw, err := os.ReadFile(r.Path())
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]Entry{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("the registry must stay a flat map of entries, which is what every build reads: %v\n%s", err, raw)
	}
	return m
}

// Every write stamps the file, and the stamp is not a name.
func TestFormatIsStampedAndHidden(t *testing.T) {
	r := Open(t.TempDir(), "doze")
	if _, err := r.Claim(Qualified("db", "shop")); err != nil {
		t.Fatal(err)
	}
	stamp, ok := readRaw(t, r)[formatKey]
	if !ok || stamp.Format != FormatVersion || stamp.PID != os.Getpid() {
		t.Fatalf("stamp = %+v (present %v), want format %d from this process", stamp, ok, FormatVersion)
	}
	if _, leaked := r.Snapshot()[formatKey]; leaked {
		t.Fatal("the stamp must not appear among the names")
	}
	if ip := r.Resolve("_format"); ip != nil {
		t.Fatalf("the stamp resolved to %v", ip)
	}
}

// A file from before the version existed has no stamp. It is read as it is and
// stamped on the next write.
func TestAnUnstampedFileIsRead(t *testing.T) {
	home := t.TempDir()
	old := map[string]Entry{"db.shop.doze": {IP: "127.0.0.20", PID: os.Getpid(), Owner: "doze", Tier: TierQualified}}
	raw, _ := json.Marshal(old)
	if err := os.WriteFile(filepath.Join(home, FileName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	r := Open(home, "doze-aws")
	if ip := r.Resolve("db.shop.doze"); ip == nil || ip.String() != "127.0.0.20" {
		t.Fatalf("an unstamped file's names must resolve, got %v", ip)
	}
	if stamp := readRaw(t, r)[formatKey]; stamp.Format != FormatVersion {
		t.Fatalf("reading should have stamped the file, got %+v", stamp)
	}
}

// A file from a newer build is left exactly as it is: this build does not know
// what it would be throwing away.
func TestANewerFileIsNotTouched(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, FileName)
	newer := []byte(`{"_format":{"ip":"","pid":1,"owner":"doze","tier":"","format":99},"db.shop.doze":{"ip":"127.0.0.20","pid":1,"owner":"doze","tier":"qualified","shape":"something this build has never heard of"}}`)
	if err := os.WriteFile(path, newer, 0o644); err != nil {
		t.Fatal(err)
	}
	r := Open(home, "doze-aws")
	_, err := r.Claim(Qualified("aws", "shop"))
	var nf *ErrNewerFormat
	if !errors.As(err, &nf) || nf.Have != 99 || nf.Want != FormatVersion {
		t.Fatalf("claiming into a newer file = %v, want ErrNewerFormat{99, %d}", err, FormatVersion)
	}
	if after, _ := os.ReadFile(path); string(after) != string(newer) {
		t.Fatalf("a newer file was rewritten:\n%s", after)
	}
	if got := r.Snapshot(); len(got) != 0 {
		t.Fatalf("names from a file this build cannot read must not be served: %v", got)
	}
}
