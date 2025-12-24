package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/influxdata/telegraf/controller/pb"
)

var (
	serverAddress string
	agentCode     string
	rootCmd       = &cobra.Command{Use: "client"}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&serverAddress, "server", "s", "localhost:10380", "gRPC server address")
	rootCmd.PersistentFlags().StringVarP(&agentCode, "agent", "a", "", "Agent code")
	execCommandCmd.Flags().Bool("continuous", false, "Run the command in continuous mode")

	// Package commands
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(restartCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(getConfigsCmd)
	rootCmd.AddCommand(applyConfigsCmd)
	rootCmd.AddCommand(getRecentLogsCmd)

	// Command service commands
	rootCmd.AddCommand(execCommandCmd)
	rootCmd.AddCommand(execCommandSignalCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getPackageClient() (context.Context, pb.PackageClient, *grpc.ClientConn) {
	conn, err := grpc.Dial(serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("agent-code", agentCode))
	return ctx, pb.NewPackageClient(conn), conn
}

func getCommandClient() (context.Context, pb.CommandClient, *grpc.ClientConn) {
	conn, err := grpc.Dial(serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("agent-code", agentCode))
	return ctx, pb.NewCommandClient(conn), conn
}

var startCmd = &cobra.Command{
	Use:   "start [package]",
	Short: "Start a package",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn := getPackageClient()
		defer conn.Close()

		_, err := client.Start(ctx, &pb.StartReq{Package: args[0]})
		if err != nil {
			log.Fatalf("Error starting package: %v", err)
		}
		fmt.Println("Package started successfully")
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop [package]",
	Short: "Stop a package",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn := getPackageClient()
		defer conn.Close()

		_, err := client.Stop(ctx, &pb.StopReq{Package: args[0]})
		if err != nil {
			log.Fatalf("Error stopping package: %v", err)
		}
		fmt.Println("Package stopped successfully")
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart [package]",
	Short: "Restart a package",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn := getPackageClient()
		defer conn.Close()

		_, err := client.Restart(ctx, &pb.RestartReq{Package: args[0]})
		if err != nil {
			log.Fatalf("Error restarting package: %v", err)
		}
		fmt.Println("Package restarted successfully")
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all packages",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn := getPackageClient()
		defer conn.Close()

		resp, err := client.PackageList(ctx, &emptypb.Empty{})
		if err != nil {
			log.Fatalf("Error listing packages: %v", err)
		}
		fmt.Printf("Agent Code: %s\n", resp.AgentCode)
		for _, pkg := range resp.Packages {
			fmt.Printf("Package: %s, Running: %v, Schema: %s, Version: %s, Running Duration: %d\n",
				pkg.Package, pkg.IsRunning, pkg.Schema, pkg.Version, pkg.RunningDuration)
		}
	},
}

var getConfigsCmd = &cobra.Command{
	Use:   "get-configs [package]",
	Short: "Get configurations of a package",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn := getPackageClient()
		defer conn.Close()

		resp, err := client.GetConfigs(ctx, &pb.GetConfigsReq{Package: args[0]})
		if err != nil {
			log.Fatalf("Error getting package configurations: %v", err)
		}
		for _, config := range resp.Configs {
			fmt.Printf("Key: %s\nContent:\n%s\n\n", config.FileName, config.Content)
		}
	},
}

var applyConfigsCmd = &cobra.Command{
	Use:   "apply-configs [package] [config_file]",
	Short: "Apply configurations to a package from a file",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn := getPackageClient()
		defer conn.Close()

		packageName := args[0]
		configFile := args[1]

		// 读取配置文件内容
		content, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Error reading config file: %v", err)
		}

		configs := []*pb.ConfigItem{{FileName: "/home/jacky/.config/uniops-telegraf/uniops-telegraf.conf", Content: string(content)}}
		resp, err := client.ApplyConfigs(ctx, &pb.ApplyConfigsReq{
			Package: packageName,
			Configs: configs,
		})
		if err != nil {
			log.Fatalf("Error applying package configurations: %v", err)
		}

		fmt.Printf("Apply configs result: Success=%v, Message=%s\n", resp.Success, resp.Message)

		if resp.Success {
			fmt.Println("Updated files:")
			for _, file := range resp.UpdatedFiles {
				fmt.Printf("  - %s (%d bytes)\n", file.FileName, file.ByteCount)
			}
		}
	},
}
var execCommandCmd = &cobra.Command{
	Use:   "exec [command]",
	Short: "Execute a command on the agent",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn := getCommandClient()
		defer conn.Close()

		continuous, _ := cmd.Flags().GetBool("continuous")
		command := strings.Join(args, " ")
		stream, err := client.ExecCommand(ctx, &pb.ExecCommandReq{Command: command, Continuous: continuous})
		if err != nil {
			log.Fatalf("Error executing command: %v", err)
		}

		var commandId string
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatalf("Error receiving command output: %v", err)
			}
			if commandId == "" && resp.CommandId != "" {
				commandId = resp.CommandId
				fmt.Printf("Command ID: %s\n", commandId)
			}
			if resp.Out != "" {
				fmt.Print(resp.Out)
			}
			if resp.Err != "" {
				fmt.Fprintf(os.Stderr, resp.Err)
			}
		}
	},
}

var execCommandSignalCmd = &cobra.Command{
	Use:   "signal [command_id] [signal]",
	Short: "Send a signal to a running command",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn := getCommandClient()
		defer conn.Close()

		commandId := args[0]
		signalStr := strings.ToUpper(args[1])
		var signal pb.ExecCommandSignalType

		switch signalStr {
		case "CANCEL":
			signal = pb.ExecCommandSignalType_CANCEL
		case "PAUSE":
			signal = pb.ExecCommandSignalType_PAUSE
		case "RESUME":
			signal = pb.ExecCommandSignalType_RESUME
		default:
			log.Fatalf("Invalid signal: %s. Must be CANCEL, PAUSE, or RESUME", signalStr)
		}

		resp, err := client.ExecCommandSignal(ctx, &pb.ExecCommandSignalReq{
			CommandId: commandId,
			Signal:    signal,
		})
		if err != nil {
			log.Fatalf("Error sending command signal: %v", err)
		}

		if resp.Success {
			fmt.Printf("Signal %s sent successfully to command %s\n", signalStr, commandId)
		} else {
			fmt.Printf("Failed to send signal %s to command %s\n", signalStr, commandId)
		}
	},
}

var getRecentLogsCmd = &cobra.Command{
	Use:   "get-logs [package] [count]",
	Short: "Get recent logs for a package",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn := getPackageClient()
		defer conn.Close()

		packageName := args[0]
		count, err := strconv.Atoi(args[1])
		if err != nil {
			log.Fatalf("Invalid count: %v", err)
		}

		resp, err := client.GetRecentLogs(ctx, &pb.GetRecentLogsReq{
			Package: packageName,
			Count:   int32(count),
		})
		if err != nil {
			log.Fatalf("Error getting recent logs: %v", err)
		}

		fmt.Printf("Recent logs for package %s:\n", packageName)
		for i, log := range resp.Logs {
			fmt.Printf("%d: %s\n", i+1, log)
		}
	},
}
