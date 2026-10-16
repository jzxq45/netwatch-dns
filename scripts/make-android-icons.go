//go:build ignore

// make-android-icons renders launcher icons (shield + radar waves on a dark
// navy rounded square) into android/app/src/main/res/mipmap-*/ic_launcher.png.
// Pure stdlib: supersampled rasterizer, no external deps.
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

var (
	bg      = color.RGBA{11, 18, 32, 255}   // dark navy
	shield  = color.RGBA{77, 163, 255, 255} // accent blue
	accent2 = color.RGBA{126, 226, 184, 255}
	white   = color.RGBA{235, 242, 250, 255}
)

// sizes maps mipmap dir to edge length in px.
var sizes = map[string]int{
	"mipmap-mdpi": 48, "mipmap-hdpi": 72, "mipmap-xhdpi": 96,
	"mipmap-xxhdpi": 144, "mipmap-xxxhdpi": 192,
}

// shield outline as a closed polygon, coords in [-1,1], y down.
var shieldPoly = []pt{
	{-0.62, -0.72}, {0.62, -0.72}, {0.62, 0.02},
	{0.52, 0.28}, {0.30, 0.52}, {0.12, 0.64}, {0, 0.70},
	{-0.12, 0.64}, {-0.30, 0.52}, {-0.52, 0.28}, {-0.62, 0.02},
}

type pt struct{ x, y float64 }

func main() {
	const out = "android/app/src/main/res"
	if err := os.MkdirAll("android/app/src/main/res", 0o755); err != nil {
		panic(err)
	}
	for dir, size := range sizes {
		dst := filepath.Join(out, dir)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			panic(err)
		}
		img := render(size)
		f, err := os.Create(filepath.Join(dst, "ic_launcher.png"))
		if err != nil {
			panic(err)
		}
		if err := png.Encode(f, img); err != nil {
			panic(err)
		}
		if err := f.Close(); err != nil {
			panic(err)
		}
		fmt.Println("wrote", filepath.Join(dst, "ic_launcher.png"), size)
	}
}

func render(size int) image.Image {
	const ss = 4 // supersample
	n := size * ss
	c := image.NewRGBA(image.Rect(0, 0, n, n))
	bg := toF(bg)

	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			fx := float64(x)/float64(n)*2 - 1 // -1..1
			fy := float64(y)/float64(n)*2 - 1
			c2 := bg
			if rounded(fx, fy, 0.16) { // background rounded square
				c2 = bg
				// radar arcs (thin rings around center, gap towards top-right handled by sweep)
				r := math.Hypot(fx, fy)
				theta := math.Atan2(fy, fx) // -pi..pi, y down => up is -pi/2
				if ringHit(r) && sweepOK(theta) {
					d := ringAlpha(r)
					c2 = mix(c2, toF(accent2), d*0.55)
				}
				if inShield(fx*1.25, fy*1.25) {
					c2 = mix(c2, toF(shield), 1)
				}
				// small radar dot top-right of shield
				dx, dy := fx-0.52, fy+0.52
				if math.Hypot(dx, dy) < 0.07 {
					c2 = mix(c2, toF(white), 1)
				}
			}
			ifx, ify := uint8(clamp(c2[0]*255)), uint8(clamp(c2[1]*255))
			ib := uint8(clamp(c2[2] * 255))
			ia := uint8(clamp(c2[3] * 255))
			c.SetRGBA(x, y, color.RGBA{ifx, ify, ib, ia})
		}
	}
	// downscale (box average) to size
	outImg := image.NewRGBA(image.Rect(0, 0, size, size))
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(dst, dst.Bounds(), image.NewUniform(color.Transparent), image.Point{}, draw.Src)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a uint32
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					pr, pg, pb, pa := c.At(x*ss+sx, y*ss+sy).RGBA()
					r += pr / uint32(ss*ss)
					g += pg / uint32(ss*ss)
					b += pb / uint32(ss*ss)
					a += pa / uint32(ss*ss)
				}
			}
			outImg.Set(x, y, color.RGBA64{uint16(r), uint16(g), uint16(b), uint16(a)})
		}
	}
	return outImg
}

func rounded(x, y, rad float64) bool {
	// inside a rounded square spanning -1..1 with corner radius rad*2 (unit coords)
	corner := 0.32
	ax, ay := math.Abs(x), math.Abs(y)
	if ax <= 1-corner || ay <= 1-corner {
		return ax <= 1 && ay <= 1
	}
	dx, dy := ax-(1-corner), ay-(1-corner)
	return dx*dx+dy*dy <= corner*corner
}

func ringHit(r float64) bool { return r > 0.30 && r < 0.98 }

func sweepOK(theta float64) bool {
	// gap at top-right (theta near -pi/4): sweep from 0.5rad..2pi-0.35rad
	return theta > 0.4 || theta < -1.1
}

func ringAlpha(r float64) float64 {
	d := r - 0.64 // center ring
	return 1 - math.Min(1, math.Abs(d)*2.6)
}

func inShield(x, y float64) bool { return pip(shieldPoly, x, y) }

func pip(poly []pt, x, y float64) bool {
	inside := false
	j := len(poly) - 1
	for i := 0; i < len(poly); i++ {
		xi, yi := poly[i].x, poly[i].y
		xj, yj := poly[j].x, poly[j].y
		if (yi > y) != (yj > y) && x < (xj-xi)*(y-yi)/(yj-yi)+xi {
			inside = !inside
		}
		j = i
	}
	return inside
}

func toF(c color.Color) [4]float64 {
	r, g, b, a := c.RGBA()
	return [4]float64{float64(r) / 65535, float64(g) / 65535, float64(b) / 65535, float64(a) / 65535}
}

func mix(a, b [4]float64, t float64) [4]float64 {
	return [4]float64{a[0] + (b[0]-a[0])*t, a[1] + (b[1]-a[1])*t, a[2] + (b[2]-a[2])*t, a[3] + (b[3]-a[3])*t}
}

func clamp(v float64) float64 { return math.Max(0, math.Min(1, v)) }
