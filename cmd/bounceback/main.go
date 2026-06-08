package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/D00Movenok/BounceBack/internal/audit"
	"github.com/D00Movenok/BounceBack/internal/common"
	"github.com/D00Movenok/BounceBack/internal/database"
	"github.com/D00Movenok/BounceBack/internal/proxy"
)

const banner = `
 ╭─╮   ____       
 ╰─╯   │   ╲ ____ ╭──╮ ┬  ┬ ┬  ┬ ╭──╮ ╭──╮
     ╲ │___╱╱   │ │  │ │  │ │╲╲│ │    ├──╯
       │   ╲╲___│ ╰──╯ ╰──╯ ┴  ┴ ╰──╯ ╰──╯
     ╱ │___╱╱   │ ╭──╮ ╭──╮ ┬ ┌    v%s
            ╲___│ ├──┤ │    ├─┴╮   @d00movenok
   ╱              ┴  ┴ ╰──╯ ┴  ┴

:: BounceBack - Stealth redirector for your redteam operations.

`

var (
	version = "0.0.0-next"

	configFile = pflag.StringP(
		"config",
		"c",
		"config.yml",
		"Path to the config file in YAML format",
	)
	logFile = pflag.StringP(
		"log",
		"l",
		"bounceback.log",
		"Path to the log file",
	)
	auditLogFile = pflag.String(
		"audit-log",
		"bounceback-audit-events.jsonl",
		"Path to the structured decision audit log",
	)
	storagePath = pflag.String(
		"storage",
		"storage",
		"Path to the verdict storage directory",
	)
	removePermanentReject = pflag.String(
		"remove-permanent-reject",
		"",
		"Clear the permanent reject state for an IP and exit",
	)
	verbose = pflag.CountP(
		"verbose",
		"v",
		"Verbose logging (0 = info, 1 = debug, 2+ = trace)",
	)
)

func main() {
	fmt.Fprintf(os.Stdout, banner[1:], version)

	initPflag()
	initLogger()
	initAuditLogger()
	setLogLevel()

	db := createKeyValueStorage()
	defer db.DB.Close()

	if *removePermanentReject != "" {
		clearPermanentReject(db, *removePermanentReject)
		return
	}

	parseConfig()
	cfg := parseProxyConfig()
	log.Debug().Any("config", cfg).Msg("Parsed config")

	m := runProxyManager(db, cfg)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	<-c

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Second*5, //nolint:mnd
	)
	defer cancel()

	shutdownProxyManager(ctx, m)

	log.Info().Msg("Shutdown successful")
}

func initPflag() {
	pflag.ErrHelp = errors.New("") //nolint:reassign // remove error from output
	pflag.Usage = func() {         //nolint:reassign // nice help message
		fmt.Fprintln(os.Stdout, "Usage of BounceBack:")
		pflag.PrintDefaults()
	}
	pflag.Parse()
}

func initLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix //nolint:reassign // default time formatting

	fileWriter, err := os.OpenFile(
		*logFile,
		os.O_WRONLY|os.O_CREATE|os.O_APPEND,
		0600,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't create/open log file")
	}
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}

	log.Logger = log.Output( //nolint:reassign // default logger
		zerolog.MultiLevelWriter(
			consoleWriter,
			fileWriter,
		),
	)
}

func initAuditLogger() {
	fileWriter, err := os.OpenFile(
		*auditLogFile,
		os.O_WRONLY|os.O_CREATE|os.O_APPEND,
		0600,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't create/open audit log file")
	}
	audit.Configure(fileWriter)
}

func setLogLevel() {
	switch *verbose {
	case 0:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case 1:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}

	log.Info().
		Stringer("verbosity", zerolog.GlobalLevel()).
		Msg("LogLevel")
}

func parseConfig() {
	viper.SetConfigFile(*configFile)
	viper.SetConfigType("yaml")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Can't read config from yaml")
	}
}

func createKeyValueStorage() *database.DB {
	log.Info().Msg("Creating storage")
	db, err := database.New(*storagePath, false)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't create key/value storage")
	}
	return db
}

func clearPermanentReject(db *database.DB, rawIP string) {
	ip, err := netip.ParseAddr(rawIP)
	if err != nil {
		log.Fatal().Err(err).Str("ip", rawIP).Msg("Invalid IP address")
	}
	ip = ip.Unmap()

	cleared, err := db.ClearRejects(ip.String())
	if err != nil {
		log.Fatal().Err(err).Stringer("ip", ip).Msg("Can't clear permanent reject")
	}

	audit.Event("permanent_reject_removed").
		Stringer("ip", ip).
		Uint("cleared_rejects", cleared).
		Str("reason", "command_line").
		Msg("permanent reject state removed")
	log.Info().
		Stringer("ip", ip).
		Uint("cleared_rejects", cleared).
		Msg("Permanent reject state removed")
}

func parseProxyConfig() *common.Config {
	cfg := new(common.Config)
	err := viper.Unmarshal(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't parse proxy config from file")
	}
	return cfg
}

func runProxyManager(db *database.DB, cfg *common.Config) *proxy.Manager {
	log.Info().Msg("Starting proxies")
	m, err := proxy.NewManager(db, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't create proxy manager")
	}

	err = m.StartAll()
	if err != nil {
		log.Fatal().Err(err).Msg("Can't start proxies")
	}

	return m
}

func shutdownProxyManager(ctx context.Context, m *proxy.Manager) {
	log.Info().Msg("Shutting down proxies")
	err := m.Shutdown(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't shutdown proxies")
	}
}
