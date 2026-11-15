package selfupdate

import (
	"context"
	"flag"
	"fmt"
	"time"
)

// RunCLI parses update flags (--check, --force, --repo, --version, --api-url)
// and checks or applies a verified self-update for binaryName. It prints human-readable
// progress and returns any error without calling os.Exit so callers remain testable.
func RunCLI(binaryName, currentVersion string, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	checkOnly := fs.Bool("check", false, "Check whether a newer release is available without modifying the binary")
	force := fs.Bool("force", false, "Download and reinstall even if already on the latest version")
	repo := fs.String("repo", "", "Public GitHub repository slug owner/repo (default: "+DefaultRepo+" or $DUCKSECRETS_UPDATE_REPO)")
	tag := fs.String("version", "", "Specific release tag to install instead of 'latest'")
	apiBase := fs.String("api-url", "", "Override GitHub API base URL ($DUCKSECRETS_UPDATE_API_URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	opts := Options{
		BinaryName:     binaryName,
		CurrentVersion: currentVersion,
		TargetTag:      *tag,
		Repo:           *repo,
		APIBase:        *apiBase,
		Force:          *force,
	}
	if *checkOnly {
		info, err := Check(ctx, opts)
		if err != nil {
			return err
		}
		fmt.Printf("Repository:      %s\n", info.Repo)
		fmt.Printf("Current version: %s\n", info.CurrentVersion)
		fmt.Printf("Latest release:  %s\n", info.LatestVersion)
		if info.ReleaseURL != "" {
			fmt.Printf("Release URL:     %s\n", info.ReleaseURL)
		}
		if info.UpdateAvailable {
			fmt.Printf("Status:          update available (run '%s update' to install)\n", binaryName)
		} else {
			fmt.Println("Status:          up to date")
		}
		return nil
	}

	res, err := Apply(ctx, opts)
	if err != nil {
		return err
	}
	if !res.Updated {
		fmt.Printf("%s is already up to date (%s, latest=%s from %s)\n", binaryName, res.CurrentVersion, res.LatestVersion, res.Repo)
		return nil
	}
	fmt.Printf("Updated %s (%s -> %s, sha256=%s)\n", res.TargetPath, res.CurrentVersion, res.LatestVersion, res.ActualSHA)
	if binaryName == "ducksecretsd" {
		fmt.Println("Restart the ducksecrets service (e.g. 'systemctl restart ducksecrets') to run the new version.")
	}
	return nil
}
