package sup

import (
	"fmt"
	"io"
	"os/exec"
	"path"
	"strings"

	"github.com/pkg/errors"
)

// Copying dirs/files over SSH using TAR.
// tar -C . -cvzf - $SRC | ssh $HOST "tar -C $DST -xvzf -"

// RemoteTarCommand returns command to be run on remote SSH host
// to properly receive the created TAR stream.
// TODO: Check for relative directory.
func RemoteTarCommand(dir string) string {
	return fmt.Sprintf("tar -C \"%s\" -xzf -", dir)
}

func IsValidPath(filePath string) bool {
	if strings.Index(filePath, "..") >= 0 {
		return false
	}
	return true
}

func LocalTarCmdArgs(filePath, exclude string) []string {
	args := []string{}

	for {
		if strings.Index(filePath, ".") == 0 {
			filePath = strings.TrimLeft(filePath, ".")
			continue
		}
		if strings.Index(filePath, "/") == 0 {
			filePath = strings.TrimLeft(filePath, "/")
		}
		break
	}

	// Added pattens to exclude from tar compress
	excludes := strings.Split(exclude, ",")
	for _, exclude := range excludes {
		trimmed := strings.TrimSpace(exclude)
		if trimmed != "" {
			args = append(args, `--exclude=`+trimmed)
		}
	}

	dir := path.Dir(filePath)
	dir = fmt.Sprintf("./%s", dir)

	base := path.Base(filePath)

	args = append(args, "-C", dir, "-czf", "-", base)
	fmt.Println("XXXXXXXXXXXX: args", args)
	return args
}

// NewTarStreamReader creates a tar stream reader from a local path.
// TODO: Refactor. Use "archive/tar" instead.
func NewTarStreamReader(cwd, path, exclude string) (io.Reader, error) {
        //  -C ./. -czf - uniops-agent
	cmd := exec.Command("tar", LocalTarCmdArgs(path, exclude)...)
	cmd.Dir = cwd
	fmt.Println("YYYYYYYYYYY: cwd: ", cwd)
	stdout, err := cmd.StdoutPipe()

	if err != nil {
		return nil, errors.Wrap(err, "tar: stdout pipe failed")
	}

	if err := cmd.Start(); err != nil {
		return nil, errors.Wrap(err, "tar: starting cmd failed")
	}

	return stdout, nil
}
