package names

import (
	"os"
	"os/exec"
	"testing"
)

func TestApexAddressIsFixed(t *testing.T) {
	// These values go into people's /etc/hosts at setup time, before anything
	// is running. Changing one silently strands every machine already set up,
	// so it should take a deliberate edit to this test to move them.
	r := Open(t.TempDir(), "doze-aws")
	for service, want := range map[string]string{"aws": "127.0.0.2", "kafka": "127.0.0.3"} {
		lease, err := r.Claim(Apex(service))
		if err != nil {
			t.Fatalf("Claim(%s): %v", service, err)
		}
		if got := lease.IP.String(); got != want {
			t.Errorf("%s.doze = %s, want %s", service, got, want)
		}
	}
}

func TestApexNameIsFirstComeAndNamesTheHolder(t *testing.T) {
	home := t.TempDir()
	first := Open(home, "doze-aws")
	if _, err := first.Claim(Apex("aws")); err != nil {
		t.Fatal(err)
	}

	// A second process — a doze stack, say — wants the same apex name. It must
	// be refused and told who has it, not silently win or silently lose.
	second := Open(home, "doze")
	second.pid = livePID(t) // a different, living process
	_, err := second.Claim(Apex("aws"))
	held, ok := Held(err)
	if !ok {
		t.Fatalf("second claim err = %v, want ErrHeld", err)
	}
	if held.PID != os.Getpid() || held.Owner != "doze-aws" {
		t.Errorf("held by pid %d (%s), want pid %d (doze-aws)", held.PID, held.Owner, os.Getpid())
	}

	// And the loser's qualified name is unaffected — that is what makes losing
	// the apex race cost nothing functional.
	if _, err := second.Claim(Qualified("cloud", "shop")); err != nil {
		t.Errorf("qualified claim after losing apex: %v", err)
	}
}

func TestDeadHolderIsPruned(t *testing.T) {
	home := t.TempDir()
	// A process that claimed the name and then died without releasing it —
	// a kill -9, which no shutdown hook survives.
	ghost := Open(home, "doze-aws")
	ghost.pid = deadPID(t)
	if _, err := ghost.Claim(Apex("aws")); err != nil {
		t.Fatal(err)
	}

	live := Open(home, "doze-kafka")
	lease, err := live.Claim(Apex("aws"))
	if err != nil {
		t.Fatalf("claim over a dead holder: %v", err)
	}
	if lease.IP.String() != "127.0.0.2" {
		t.Errorf("ip = %s, want 127.0.0.2", lease.IP)
	}
}

func TestResolveAnswersEveryPeersNames(t *testing.T) {
	// The property the whole design rests on: a registry handle owned by one
	// binary resolves names another binary registered.
	home := t.TempDir()
	aws := Open(home, "doze-aws")
	if _, err := aws.Claim(Apex("aws")); err != nil {
		t.Fatal(err)
	}
	kafka := Open(home, "doze-kafka")
	if _, err := kafka.Claim(Apex("kafka")); err != nil {
		t.Fatal(err)
	}

	// doze-kafka's handle answers for doze-aws's name.
	if ip := kafka.Resolve("aws.doze"); ip == nil || ip.String() != "127.0.0.2" {
		t.Errorf("kafka.Resolve(aws.doze) = %v, want 127.0.0.2", ip)
	}
	if ip := aws.Resolve("kafka.doze"); ip == nil || ip.String() != "127.0.0.3" {
		t.Errorf("aws.Resolve(kafka.doze) = %v, want 127.0.0.3", ip)
	}
	// Trailing dot and case are how a resolver actually receives names.
	if ip := aws.Resolve("AWS.Doze."); ip == nil {
		t.Error("Resolve is not normalizing case and the trailing dot")
	}
	// A name nobody registered is not ours to answer.
	if ip := aws.Resolve("nope.doze"); ip != nil {
		t.Errorf("unregistered name resolved to %v, want nil", ip)
	}
	if ip := aws.Resolve("example.com"); ip != nil {
		t.Errorf("out-of-zone name resolved to %v", ip)
	}
}

func TestReleaseFreesTheName(t *testing.T) {
	home := t.TempDir()
	r := Open(home, "doze-aws")
	lease, err := r.Claim(Apex("aws"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if ip := r.Resolve("aws.doze"); ip != nil {
		t.Errorf("released name still resolves to %v", ip)
	}
	other := Open(home, "doze")
	other.pid = livePID(t)
	if _, err := other.Claim(Apex("aws")); err != nil {
		t.Errorf("claim after release: %v", err)
	}
}

func TestQualifiedAddressesAreStableAndDistinct(t *testing.T) {
	home := t.TempDir()
	r := Open(home, "doze")
	a, err := r.Claim(Qualified("cloud", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Claim(Qualified("cache", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	if a.IP.Equal(b.IP) {
		t.Fatalf("two services share %v", a.IP)
	}
	for _, ip := range []string{a.IP.String(), b.IP.String()} {
		if ip == resolverIP {
			t.Errorf("allocated the resolver's own address %s", ip)
		}
		if ip == "127.0.0.2" || ip == "127.0.0.3" {
			t.Errorf("allocated %s, which is reserved for an apex name", ip)
		}
	}
	// Same name, fresh registry → same address, with nothing persisted.
	again := Open(t.TempDir(), "doze")
	c, err := again.Claim(Qualified("cloud", "shop"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IP.Equal(a.IP) {
		t.Errorf("cloud.shop.doze moved from %v to %v across registries", a.IP, c.IP)
	}
}

func TestUnknownApexServiceIsRefused(t *testing.T) {
	// An apex name with no reserved address cannot be invented at runtime: the
	// address has to be in /etc/hosts, written before this process existed.
	r := Open(t.TempDir(), "doze")
	if _, err := r.Claim(Apex("mystery")); err == nil {
		t.Fatal("claimed an apex name with no reserved address")
	}
}

// livePID returns the pid of a process that exists but is not this one.
func livePID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	return cmd.Process.Pid
}

// deadPID returns the pid of a process that has exited and been reaped.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.ProcessState.Pid()
}
