package podman

import (
	"reflect"
	"testing"
)

func TestBuildArgs(t *testing.T) {
	got := BuildArgs("example/image:dev", "/tmp/Containerfile")
	want := []string{"build", "-t", "example/image:dev", "-f", "/tmp/Containerfile", "."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildArgs = %v want %v", got, want)
	}
}

func TestRunArgs(t *testing.T) {
	got := RunArgs(RunOptions{
		Name:        "gfs-dev",
		Image:       "example/image:dev",
		Privileged:  true,
		PIDHost:     true,
		Interactive: true,
		Remove:      true,
		SecurityOpts: []string{
			"seccomp=unconfined",
			"apparmor=unconfined",
		},
		Mounts: []Mount{
			{Host: "/sys/kernel/btf", Container: "/sys/kernel/btf", Options: "ro"},
			{Host: "/tmp/reports", Container: "/reports", Options: "Z"},
		},
		Command: []string{"/bin/bash"},
	})
	want := []string{
		"run", "--rm", "-it", "--name", "gfs-dev", "--privileged", "--pid=host",
		"--security-opt", "seccomp=unconfined",
		"--security-opt", "apparmor=unconfined",
		"-v", "/sys/kernel/btf:/sys/kernel/btf:ro",
		"-v", "/tmp/reports:/reports:Z",
		"example/image:dev", "/bin/bash",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RunArgs = %v want %v", got, want)
	}
}

func TestImageExistsArgs(t *testing.T) {
	got := ImageExistsArgs("example/image:dev")
	want := []string{"image", "exists", "example/image:dev"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ImageExistsArgs = %v want %v", got, want)
	}
}
