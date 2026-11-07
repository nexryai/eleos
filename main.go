package main

import (
	"flag"
	"fmt"
	"os"
	"roscaelum/internal/config"
	"roscaelum/internal/firewall"
	"roscaelum/internal/log"
)

func showHelp() {
	fmt.Println("roscaelum firewall - Yet another human-friendly firewall \n\n",
		"(c)2023 nexryai\nThis program is licensed under the MIT License, and anyone can audit and contribute to it.\n\n\n",
		"[usage]\n",
		"Enable firewall:\n  ▶ rcfctl enable\n\n",
		"Apply rules when configuration is updated:\n  ▶ rcfctl apply\n\n",
		"Disable firewall:\n  ▶ rcfctl disable\n\n",
		"[options]\n",
		"-f [PATH]: Specify the path to the configuration file (Default: /etc/roscaelum.yml)")
}

func main() {
	configFilePath := flag.String("f", "/etc/roscaelum.yml", "Path of cfg.yml")
	debugMode := flag.Bool("debug", false, "Enable debug mode")

	flag.Parse()

	// 現状デバッグモードはログ以外に影響を与えないが将来的に変わる可能性もある。
	// 環境変数以外にもいいやり方あるかもしれない。毎回configをcore.MsgDbg呼ぶ時に引数渡すのは面倒だから避けたい。
	if *debugMode {
		log.MsgInfo("debug mode!")
		err := os.Setenv("ROSCAELUM_DEBUG_MODE", "true")
		if err != nil {
			log.MsgFatalAndExit(err, "Failed to set environment variable.")
		}
	} else {
		err := os.Setenv("ROSCAELUM_DEBUG_MODE", "false")
		if err != nil {
			log.MsgFatalAndExit(err, "Failed to set environment variable.")
		}
	}

	log.MsgDebug("configFilePath: " + *configFilePath)

	cfg := config.LoadConfig(*configFilePath)

	operation := flag.Arg(0)

	switch operation {
	case "apply":
		if err := firewall.Apply(&cfg); err != nil {
			log.MsgFatalAndExit(err, "Failed to apply firewall rules.")
		}
		log.MsgInfo("Firewall settings have been applied successfully.")
	case "enable":
		if err := firewall.Apply(&cfg); err != nil {
			log.MsgFatalAndExit(err, "Failed to enable firewall.")
		}
		log.MsgInfo("roscaelum firewall is enabled.")
	case "disable":
		if err := firewall.Disable(); err != nil {
			log.MsgFatalAndExit(err, "Failed to disable firewall.")
		}
		log.MsgInfo("roscaelum firewall is disabled.")
	case "":
		//コマンド説明
		showHelp()
	default:
		log.MsgErr("Invalid args!\n")
		showHelp()
		os.Exit(1)
	}
}
