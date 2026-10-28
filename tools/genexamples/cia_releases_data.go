package main

// exampleReleases lists the releases the examples archive: three that were
// already running when the window begins, and the signed frontend release that
// replaces a build deployed by hand.
func exampleReleases() ([]*release, error) {
	specs := []releaseSpec{
		{service: "status", version: "0.2.0", commit: fakeHex("status 0.2.0"),
			built: "2026-09-29T09:12:44Z", seen: "2026-09-29T09:30:02Z", done: "2026-09-29T09:31:07Z", files: []fileSpec{
				{"404.html", "/404.html", 1_804}, {"index.html", "/index.html", 6_120}, {"sw.js", "/sw.js", 4_310},
				{"assets/icon.svg", "/assets/icon.svg", 912}, {"assets/app.js", "/assets/app.js", 28_440},
				{"assets/app.css", "/assets/app.css", 9_210}, {"incidents/index.html", "/incidents/index.html", 3_015},
				{"timestamps/index.html", "/timestamps/index.html", 2_890}, {"verify/index.html", "/verify/index.html", 3_220},
				{"witness/index.html", "/witness/index.html", 3_015},
			}},
		{service: "vault", version: "0.1.29", commit: fakeHex("vault 0.1.29"), built: "2026-09-28T16:02:11Z", seen: "2026-09-28T16:20:01Z", done: "2026-09-28T16:21:09Z",
			files: []fileSpec{
				{"assets/favicon.svg", "/favicon.svg", 912}, {"assets/openapi.json", "/openapi.json", 184_233},
				{"worker/index.js", "", 1_893_301}, {"worker/wrangler.json", "", 4_120},
			}},
		{service: "sign", version: "0.1.18", commit: fakeHex("sign 0.1.18"), built: "2026-09-25T13:40:30Z", seen: "2026-09-25T14:00:01Z", done: "2026-09-25T14:01:12Z",
			files: []fileSpec{
				{"assets/index.html", "/index.html", 2_410}, {"assets/app.js", "/app.js", 148_220},
				{"assets/app.css", "/app.css", 9_870}, {"assets/favicon.svg", "/favicon.svg", 880},
				{"worker/index.js", "", 1_204_110}, {"worker/wrangler.json", "", 3_980},
			}},
		{service: "frontend", version: "1.0.29+client.0.42.2", commit: fakeHex("frontend 1.0.29"), built: "2026-10-01T09:41:12Z", seen: "2026-10-01T10:00:01Z",
			done: "2026-10-01T10:03:21Z", files: []fileSpec{
				{"_headers", "", 612}, {"_redirects", "", 240}, {"index.html", "/index.html", 14_330},
				{"app/index.html", "/app/index.html", 3_120}, {"app/assets/client.js", "/app/assets/client.js", 612_300},
				{"app/assets/client.css", "/app/assets/client.css", 48_900}, {"favicon.svg", "/favicon.svg", 880},
				{"robots.txt", "/robots.txt", 120},
			}},
	}
	out := make([]*release, len(specs))
	for i, s := range specs {
		var err error
		if out[i], err = newRelease(s); err != nil {
			return nil, err
		}
	}
	return out, nil
}
