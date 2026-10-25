package podman

const DefaultImage = "localhost/gofengshui-e2e/glibc:dev"

type Mount struct {
	Host      string
	Container string
	Options   string
}

type RunOptions struct {
	Name         string
	Image        string
	Privileged   bool
	PIDHost      bool
	Interactive  bool
	Remove       bool
	SecurityOpts []string
	Mounts       []Mount
	Command      []string
}

func BuildArgs(tag, containerfile string) []string {
	return []string{"build", "-t", tag, "-f", containerfile, "."}
}

func ImageExistsArgs(image string) []string {
	return []string{"image", "exists", image}
}

func RunArgs(opts RunOptions) []string {
	args := []string{"run"}
	if opts.Remove {
		args = append(args, "--rm")
	}
	if opts.Interactive {
		args = append(args, "-it")
	}
	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.Privileged {
		args = append(args, "--privileged")
	}
	if opts.PIDHost {
		args = append(args, "--pid=host")
	}
	for _, opt := range opts.SecurityOpts {
		args = append(args, "--security-opt", opt)
	}
	for _, mount := range opts.Mounts {
		spec := mount.Host + ":" + mount.Container
		if mount.Options != "" {
			spec += ":" + mount.Options
		}
		args = append(args, "-v", spec)
	}
	args = append(args, opts.Image)
	args = append(args, opts.Command...)
	return args
}
