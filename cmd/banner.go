package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
)

// mascotLines is a compact ASCII rendering of the Semar bust. Leading spaces
// define the figure's shape, so lines are left-aligned (not re-centered) inside
// the frame; only trailing space is trimmed.
var mascotLines = []string{
	"        !5m;",
	"        |8551W|",
	"     ,m%M*pZ225J          ,0KRRB.",
	"    0MoM#dZB4235Mf.     |BLRRRRRT",
	"    h*opMobqM507MP6I ;oFRRRRJDRRA.",
	"   1C$pa#whmqh%NRRROJQRRRRCI ZKRKl",
	"   Q539B89@#mhkIRQLQRQQQAT.   8PQB.",
	"  ,pbbh*p*o#M562RMMRRLELaB$MZIq836WI",
	"    .;kBIKHJPRQQLGRRPH6iM4%0FD%oLRNDD3O.",
	"    ;6RRRRRRRRRRBQRQERK3a41@$B1@BKRRRRPK",
	"    .oQRRRRRQQPEPRQ@MW8o@223413@1%@7BOl",
	"  .fk4CALMMLMNNQRRAo$12874447453340Wa.",
	" CERRQM9LLMOPQRRRJk@pwwOwwOO0o8*4436%f",
	"dBPJ7ANRRRRRRRRRRR%@kbZaqqqZ0oa@33230m",
	"Z@mMRRRRRRRRRRRRRDaa4$M$#B0044392544%w",
	"1, :FRRRRRRRRRRR6k#$4123432204$235661f",
	"     ZJRRRRRRDZM@MD8E8C5E54hQ6D9B8mM#",
	"      f2OD%o03WWB6588%*aoB8MRRRRHWh;",
	"       10$8EORRRRK50%B7PRRRRRQMA8d;",
	"     ,8PPPPHQRRRQLMPIBIQRRRRDHhBm.",
	"     i7RRRRRRRRRQKPRRRRRRRRRM02L",
	"      !4%Z#%opZZa28k6EB88DKQNa;",
}

var wordmark = []string{
	" ███████╗ ███████╗ ███╗   ███╗  █████╗  ██████╗ ",
	" ██╔════╝ ██╔════╝ ████╗ ████║ ██╔══██╗ ██╔══██╗",
	" ███████╗ █████╗   ██╔████╔██║ ███████║ ██████╔╝",
	" ╚════██║ ██╔══╝   ██║╚██╔╝██║ ██╔══██║ ██╔══██╗",
	" ███████║ ███████╗ ██║ ╚═╝ ██║ ██║  ██║ ██║  ██║",
	" ╚══════╝ ╚══════╝ ╚═╝     ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝",
}

// PrintBanner writes the colored SEMAR banner to w. Colors are disabled when
// noColor is set or when w is not a terminal.
func PrintBanner(w io.Writer, noColor bool) {
	if noColor || !isTerminal(w) {
		color.NoColor = true
		defer func() { color.NoColor = false }()
	}

	mascot := color.New(color.FgYellow)  // amber/ochre — Semar
	frame := color.New(color.FgHiBlack)  // dim — border frame
	dash := color.New(color.FgHiBlack)
	label := color.New(color.FgHiWhite, color.Bold)

	// Frame width = widest art line + padding.
	inner := 0
	trimmed := make([]string, len(mascotLines))
	for i, l := range mascotLines {
		trimmed[i] = strings.TrimRight(l, " ")
		if n := len([]rune(trimmed[i])); n > inner {
			inner = n
		}
	}
	inner += 4 // breathing room

	fmt.Fprintln(w)
	frame.Fprintf(w, "  ┌%s┐\n", strings.Repeat("─", inner+2))
	for _, l := range trimmed {
		pad := inner - len([]rune(l))
		frame.Fprint(w, "  │ ")
		mascot.Fprint(w, l+strings.Repeat(" ", pad))
		frame.Fprint(w, " │")
		fmt.Fprintln(w)
	}
	frame.Fprintf(w, "  └%s┘\n", strings.Repeat("─", inner+2))

	// Gradient wordmark: shift hue down each row.
	grad := []*color.Color{
		color.New(color.FgHiYellow, color.Bold),
		color.New(color.FgYellow, color.Bold),
		color.New(color.FgHiRed, color.Bold),
		color.New(color.FgRed, color.Bold),
		color.New(color.FgHiYellow, color.Bold),
		color.New(color.FgYellow, color.Bold),
	}
	fmt.Fprintln(w)
	for i, line := range wordmark {
		grad[i%len(grad)].Fprintln(w, line)
	}

	dash.Fprint(w, "   ──═╣ ")
	label.Fprint(w, "A I   A G E N T   A U D I T")
	dash.Fprint(w, " ╠═──")
	color.New(color.FgHiBlack).Fprintf(w, "   v%s\n", trimV(Version))
	color.New(color.FgYellow, color.Italic).Fprintln(w, "   \"Sing ngerti kabeh, nanging ora ngancam\"")
	fmt.Fprintln(w)
}

func trimV(v string) string {
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		return v[1:]
	}
	return v
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}
