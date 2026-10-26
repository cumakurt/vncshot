// vncshot — VNC security inventory scanner.
// Copyright (C) 2026 Cuma KURT
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// Command vncshot is a VNC security inventory scanner for authorized
// network assessments. It expands IP/CIDR/range targets, probes RFB
// endpoints, flags passwordless servers, captures their framebuffers and
// writes JSON/HTML/PDF reports.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"vncshot/report"
	"vncshot/scanner"
)

const (
	appName = "vncshot"

	authorizationNotice = `
========================================================================
  vncshot — VNC Security Inventory          LEGAL DISCLAIMER / YASAL UYARI
========================================================================

  EN — AUTHORIZED USE ONLY
  This software is published for authorized security testing, defensive
  research and education. You must scan only networks and systems you
  own or for which you hold explicit written authorization.

  Unauthorized access to, or interception of, computer systems is a
  criminal offence in most jurisdictions. You alone are solely and
  exclusively responsible for ensuring that your use of this software
  complies with all applicable local, national and international law.

  NO LIABILITY OF THE DEVELOPER
  The developer (Cuma KURT) shall NOT be held liable, under any
  circumstances and to the maximum extent permitted by applicable law,
  for any damage, loss of data, loss of profit, business interruption,
  legal claim, administrative or criminal proceeding, penalty, fine, or
  any other direct, indirect, incidental, special, consequential or
  punitive liability arising out of or in connection with the use,
  misuse, inability to use, or reliance upon this software, even if the
  developer has been advised of the possibility of such damages.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF
  THE SOFTWARE IS WITH YOU.

  TR — YALNIZCA YETKILI KULLANIM
  Bu yazılım yalnızca yetkili güvenlik testleri, savunma amaçlı araştırma
  ve eğitim amacıyla yayımlanmıştır. Yalnızca sahibi olduğunuz ya da açık
  yazılı yetkiniz bulunan ağ ve sistemleri tarayabilirsiniz.

  Yetkisiz erişim veya dinleme, çoğu yargı alanında suç teşkil eder.
  Kullanımınızın tüm yürürlükteki yerel, ulusal ve uluslararası
  mevzuata uygun olduğunu sağlamak yalnızca sizin sorumluluğunuzdadır.

  GELİŞTİRİCİNİN SORUMLULUĞU REDDEDİLİR
  Geliştirici (Cuma KURT), yazılımın kullanımından, kötüye
  kullanımından, kullanılamamasından ya da güvenilmesinden doğabilecek
  hiçbir zarar, veri kaybı, kâr kaybı, iş kesintisi, hukuki talep, idari
  ya da cezai yaptırım, para cezası veya dolaylı/sonuçsal hiçbir
  sorumluluk için, hiçbir koşulda ve yürürlükteki mevzuatın izin verdiği
  azami ölçüde, sorumlu tutulamaz.

  YAZILIM "OLDUĞU GİBİ", AÇIK VEYA ZIMNİ HİÇBİR GARANTİ OLMAKSIZIN
  SUNULMUŞTUR; SATILABİLİRLİK, BELİRLİ BİR AMACA UYGUNLUK VE İHLAL
  ETMEME GARANTİLERİ DAHİL ANCAK BUNLARLA SINIRLI OLMAMAK ÜZERE HİÇBİR
  GARANTİ VERMEZ.

  By running this tool you are deemed to have read, understood and
  accepted this disclaimer. Aracı çalıştırarak bu beyanı okuduğunuzu,
  anladığınızı ve kabul ettiğinizi beyan etmiş sayılırsınız.

  Developer / Geliştirici: Cuma KURT <cumakurt@gmail.com>
  https://github.com/cumakurt/vncshot
  License / Lisans: GPL-3.0
========================================================================
`
)

type config struct {
	target        string
	file          string
	ports         string
	timeout       time.Duration
	vncTimeout    time.Duration
	workers       int
	rate          int
	output        string
	html          string
	pdf           string
	noPDF         bool
	screenshotDir string
	shared        bool
	assumeYes     bool
}

func main() {
	cfg := parseFlags()

	if err := run(cfg); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "\nscan interrupted; partial results were written")
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config

	flag.StringVar(&cfg.target, "target", "", "single IP, CIDR or IPv4 range (e.g. 192.168.1.1, 192.168.1.0/24, 192.168.1.1-50)")
	flag.StringVar(&cfg.file, "file", "", "file with IPs/CIDRs/ranges, one per line (# comments allowed)")
	flag.StringVar(&cfg.ports, "ports", "5900", "ports to scan (list/ranges, e.g. 5900,5901-5910)")
	flag.DurationVar(&cfg.timeout, "timeout", 1*time.Second, "TCP connect timeout")
	flag.DurationVar(&cfg.vncTimeout, "vnc-timeout", 15*time.Second, "per-operation RFB handshake/capture timeout")
	flag.IntVar(&cfg.workers, "workers", 150, "concurrent scan workers")
	flag.IntVar(&cfg.rate, "rate", 200, "max new connections per second (0 = unlimited)")
	flag.StringVar(&cfg.output, "output", appName+"_report.json", "JSON report path")
	flag.StringVar(&cfg.html, "html", appName+"_report.html", "HTML report path")
	flag.StringVar(&cfg.pdf, "pdf", appName+"_report.pdf", "PDF report path")
	flag.BoolVar(&cfg.noPDF, "no-pdf", false, "skip PDF generation")
	flag.StringVar(&cfg.screenshotDir, "screenshot-dir", "screenshots", "directory for PNG captures")
	flag.BoolVar(&cfg.shared, "shared", true, "request shared RFB session (does not kick active viewers)")
	flag.BoolVar(&cfg.assumeYes, "yes", false, "skip the interactive authorization confirmation")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags]\n\n", appName)
		fmt.Fprintf(flag.CommandLine.Output(), "%s inventories VNC/RFB endpoints and captures framebuffers\n", appName)
		fmt.Fprintf(flag.CommandLine.Output(), "from servers that allow unauthenticated access.\n\n")
		fmt.Fprintln(flag.CommandLine.Output(), "Developer: Cuma KURT <cumakurt@gmail.com>")
		fmt.Fprintln(flag.CommandLine.Output(), "https://github.com/cumakurt/vncshot")
		fmt.Fprintln(flag.CommandLine.Output(), "https://www.linkedin.com/in/cuma-kurt-34414917/")
		fmt.Fprintln(flag.CommandLine.Output(), "\nFlags:")
		flag.PrintDefaults()
		fmt.Fprint(flag.CommandLine.Output(), authorizationNotice)
	}
	flag.Parse()

	return cfg
}

func run(cfg config) error {
	fmt.Fprint(os.Stderr, authorizationNotice)

	if !cfg.assumeYes {
		ok, err := confirmAuthorization()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("authorization not confirmed; aborting")
		}
	}

	ports, err := scanner.ParsePorts(cfg.ports)
	if err != nil {
		return err
	}

	targets, err := scanner.ParseTargets(cfg.target, cfg.file, ports)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "targets: %d host:port pairs | ports: %s | workers: %d | rate: %s\n",
		len(targets), cfg.ports, cfg.workers, rateText(cfg.rate))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := scanner.Options{
		ConnectTimeout: cfg.timeout,
		VNCTimeout:     cfg.vncTimeout,
		Workers:        cfg.workers,
		RatePerSec:     cfg.rate,
		ScreenshotDir:  cfg.screenshotDir,
		Shared:         cfg.shared,
		ShowProgress:   true,
	}

	results, scanErr := scanner.Run(ctx, targets, opts)

	sum := report.Summarize(results)
	if err := report.WriteJSON(cfg.output, results); err != nil {
		return err
	}
	if err := report.WriteHTML(cfg.html, results); err != nil {
		return err
	}

	if !cfg.noPDF && cfg.pdf != "" {
		if err := report.WritePDF(cfg.pdf, results); err != nil {
			// PDF is a convenience artifact; a render failure must not
			// discard the scan itself.
			fmt.Fprintf(os.Stderr, "warning: pdf generation skipped: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "pdf report: %s\n", cfg.pdf)
		}
	}

	fmt.Fprintf(os.Stderr, "\n=== summary ===\n")
	fmt.Fprintf(os.Stderr, "targets:      %d\n", sum.Targets)
	fmt.Fprintf(os.Stderr, "open:         %d\n", sum.Open)
	fmt.Fprintf(os.Stderr, "rfb services: %d\n", sum.RFB)
	fmt.Fprintf(os.Stderr, "passwordless: %d\n", sum.Passwordless)
	fmt.Fprintf(os.Stderr, "screenshots:  %d\n", sum.Screenshots)
	fmt.Fprintf(os.Stderr, "errors:       %d\n", sum.Errors)
	fmt.Fprintf(os.Stderr, "json:  %s\n", cfg.output)
	fmt.Fprintf(os.Stderr, "html:  %s\n", cfg.html)

	return scanErr
}

func rateText(rate int) string {
	if rate <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d/s", rate)
}

// confirmAuthorization makes the operator acknowledge that the scan is
// authorized before any packet leaves the host.
func confirmAuthorization() (bool, error) {
	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		// Non-interactive stdin (pipe/CI): require -yes explicitly.
		return false, fmt.Errorf("refusing to scan without confirmation in non-interactive mode; re-run with -yes after verifying authorization")
	}

	fmt.Fprint(os.Stderr, "Type 'yes' to confirm you are authorized to scan these targets: ")
	var answer string
	if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	return strings.EqualFold(strings.TrimSpace(answer), "yes"), nil
}
