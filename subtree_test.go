package names

import "testing"

// A registered name owns every name beneath it.
//
// This is what lets one process answer for hostnames it never registered and
// could not have registered. doze-aws wants to hand back URLs shaped like
// AWS's own — sqs.ap-south-1.aws.harbour.doze,
// x70an6eshc.execute-api.ap-south-1.aws.harbour.doze — and the API Gateway id
// in the second one is minted at runtime. There is no moment at which it could
// have been claimed in advance, so exact-match resolution cannot serve it even
// in principle.
func TestARegisteredNameOwnsItsSubtree(t *testing.T) {
	r := Open(t.TempDir(), "doze-aws")
	lease, err := r.Claim(Qualified("aws", "harbour"))
	if err != nil {
		t.Fatal(err)
	}
	want := lease.IP.String()

	for _, host := range []string{
		"aws.harbour.doze",                                   // the name itself
		"sqs.ap-south-1.aws.harbour.doze",                    // service + region
		"s3.us-east-1.aws.harbour.doze",                      // another service
		"receipts.s3.us-east-1.aws.harbour.doze",             // virtual-hosted bucket
		"x70an6eshc.execute-api.ap-south-1.aws.harbour.doze", // minted at runtime
		"AWS.HARBOUR.DOZE",                                   // case is not significant
		"sqs.ap-south-1.aws.harbour.doze.",                   // a trailing dot is legal
	} {
		got := r.Resolve(host)
		if got == nil {
			t.Errorf("Resolve(%s) = nil, want %s", host, want)
			continue
		}
		if got.String() != want {
			t.Errorf("Resolve(%s) = %s, want %s", host, got, want)
		}
	}
}

// The walk must not turn the resolver into a catch-all. The zone's promise is
// that an unregistered name is NXDOMAIN — "a typo fails as a name that does not
// exist rather than as a connection to the wrong thing" (docs/endpoints.md) —
// and subtree ownership is the change most likely to break it.
func TestAnUnclaimedNameStillFails(t *testing.T) {
	r := Open(t.TempDir(), "doze-aws")
	if _, err := r.Claim(Apex("aws")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Claim(Qualified("aws", "harbour")); err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{
		"doze",                      // the zone apex owns nothing
		"anything.doze",             // nobody claimed this
		"kafka.doze",                // a sibling service that is not running
		"aws.harbor.doze",           // one letter off: must NOT reach harbour
		"sqs.aws.harbor.doze",       // nor via the subtree walk
		"aws.harbour.doze.evil.com", // outside the zone entirely
		"harbour.doze",              // an ancestor of a claimed name is not itself claimed
	} {
		if got := r.Resolve(host); got != nil {
			t.Errorf("Resolve(%s) = %s, want nil — unregistered names must stay NXDOMAIN", host, got)
		}
	}
}

// Two claims where one is an ancestor of the other: the most specific wins.
// Without that, the apex would swallow every instance beneath it.
func TestTheMostSpecificNameWins(t *testing.T) {
	r := Open(t.TempDir(), "doze-aws")
	apex, err := r.Claim(Apex("aws"))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := r.Claim(Qualified("aws", "harbour"))
	if err != nil {
		t.Fatal(err)
	}
	if apex.IP.Equal(inst.IP) {
		t.Fatal("apex and instance share an address; this test cannot tell them apart")
	}

	for _, tc := range []struct{ host, want string }{
		{"sqs.ap-south-1.aws.doze", apex.IP.String()},
		{"sqs.ap-south-1.aws.harbour.doze", inst.IP.String()},
	} {
		got := r.Resolve(tc.host)
		if got == nil || got.String() != tc.want {
			t.Errorf("Resolve(%s) = %v, want %s", tc.host, got, tc.want)
		}
	}
}

// The front door has to agree with the resolver. If DNS sends a browser to an
// instance's address but the ingress does not recognise the Host, the request
// arrives and is refused — which reads as the service being down.
func TestTheFrontDoorFollowsTheSameWalk(t *testing.T) {
	r := Open(t.TempDir(), "doze-aws")
	lease, err := r.Claim(Qualified("aws", "harbour"))
	if err != nil {
		t.Fatal(err)
	}
	const backend = "127.0.0.4:4566"
	if err := lease.Route(backend); err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{
		"aws.harbour.doze",
		"sqs.ap-south-1.aws.harbour.doze",
		"sqs.ap-south-1.aws.harbour.doze:80", // a Host header may carry a port
	} {
		if got := r.routeFor(host); got != backend {
			t.Errorf("routeFor(%s) = %q, want %q", host, got, backend)
		}
	}
	if got := r.routeFor("aws.harbor.doze"); got != "" {
		t.Errorf("routeFor(typo) = %q, want \"\"", got)
	}
}

// URLFor is what gets printed and pasted, so it has to answer for a subdomain
// too — otherwise doze-aws can serve an AWS-shaped URL it cannot describe.
func TestURLForAnswersForASubdomain(t *testing.T) {
	r := Open(t.TempDir(), "doze-aws")
	lease, err := r.Claim(Qualified("aws", "harbour"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Route("127.0.0.4:4566"); err != nil {
		t.Fatal(err)
	}

	const host = "sqs.ap-south-1.aws.harbour.doze"
	// No front door is running in this test, so the port-ful form is correct.
	if got, want := r.URLFor(host), "http://"+host+":4566"; got != want {
		t.Errorf("URLFor(%s) = %q, want %q", host, got, want)
	}
	if got := r.URLFor("aws.harbor.doze"); got != "" {
		t.Errorf("URLFor(typo) = %q, want \"\"", got)
	}
}
