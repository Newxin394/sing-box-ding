package main

import (
	"os"

	"github.com/sagernet/sing-box/daemon"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

var commandAPIEBPFDeep bool

var commandAPIEBPF = &cobra.Command{
	Use:   "ebpf",
	Short: "Print eBPF inbound diagnostics",
	Long: `Print eBPF inbound diagnostics.

By default this reports each eBPF inbound's own interception state, which is
cheap enough to poll. With --deep it additionally enumerates the kernel
programs and maps this process owns; that walk is slow and only belongs in a
diagnostic run.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAPIEBPF()
	},
}

func init() {
	commandAPIEBPF.Flags().BoolVar(&commandAPIEBPFDeep, "deep", false, "enumerate owned kernel programs and maps")
	commandAPIRoot.AddCommand(commandAPIEBPF)
}

func runAPIEBPF() error {
	clientConn, client, err := createAPIClient()
	if err != nil {
		return err
	}
	defer clientConn.Close()
	response, err := client.GetEBPFDiagnostics(globalCtx, &daemon.EBPFDiagnosticsRequest{Deep: commandAPIEBPFDeep})
	if err != nil {
		return err
	}
	content, err := protojson.MarshalOptions{
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}.Marshal(response)
	if err != nil {
		return err
	}
	_, _ = os.Stdout.Write(append(content, '\n'))
	return nil
}
