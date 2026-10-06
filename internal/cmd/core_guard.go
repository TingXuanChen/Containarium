package cmd

import (
	"fmt"
	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

var coreGuardCmd = &cobra.Command{Use: "core-guard", Short: "Inspect the core infrastructure network guard"}
var coreGuardStatusCmd = &cobra.Command{Use: "status", Short: "Show the latest guard status snapshot", Args: cobra.NoArgs, RunE: runCoreGuardStatus}

func init() {
	rootCmd.AddCommand(coreGuardCmd)
	coreGuardCmd.AddCommand(coreGuardStatusCmd)
	coreGuardStatusCmd.Flags().Bool("json", false, "Print the typed status as JSON")
}

func runCoreGuardStatus(cmd *cobra.Command, _ []string) error {
	var api interface {
		GetCoreGuardStatus() (*pb.CoreGuardStatus, error)
		Close() error
	}
	var err error
	if httpMode {
		api, err = client.NewHTTPClient(serverAddr, authToken)
	} else {
		api, err = client.NewGRPCClient(serverAddr, certsDir, insecure)
	}
	if err != nil {
		return err
	}
	defer api.Close()
	status, err := api.GetCoreGuardStatus()
	if err != nil {
		return err
	}
	jsonOut, _ := cmd.Flags().GetBool("json")
	if jsonOut {
		data, err := (protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}).Marshal(status)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Mode: %s\nFirewall driver: %s\n", status.Mode, status.FirewallDriver)
	if status.StaleSince != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Stale since: %s\n", status.StaleSince)
	}
	for _, e := range status.Entries {
		fmt.Fprintf(cmd.OutOrStdout(), "%s role=%s ip=%s acl=%s attached=%t rules_applied=%t error=%s\n", e.Container, e.Role, e.Ip, e.AclName, e.Attached, e.RulesApplied, e.LastError)
	}
	return nil
}
