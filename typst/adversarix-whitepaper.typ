// Adversarix / AEGIS Labs whitepaper template (Typst 0.15).
// Reconstructed from the published PDF design so the papers can be
// maintained as source. Compile from the repo root, e.g.:
//   typst compile --root . detection-posteriors/whitepaper.typ <out.pdf>

#let navy = rgb("#17262e")
#let navy-tile = rgb("#243642")
#let teal = rgb("#2e8b82")
#let teal-bright = rgb("#4aada2")
#let orange = rgb("#d9822b")
#let ink = rgb("#3a4248")
#let heading-ink = rgb("#2b3338")
#let gray-soft = rgb("#8a949a")
#let gray-cover = rgb("#b9c3c9")
#let rule-gray = rgb("#d3dade")
#let box-bg = rgb("#e3f0ee")
#let table-header = rgb("#1c2b33")

// Callout box with teal accent bar (e.g. "Key Finding").
#let callout(title, body) = block(
  fill: box-bg,
  stroke: (left: 3.5pt + teal),
  inset: (left: 18pt, right: 18pt, top: 13pt, bottom: 15pt),
  width: 100%,
  breakable: false,
  above: 1.4em,
  below: 1.4em,
)[
  #text(fill: teal, weight: "bold", size: 10pt)[#title]
  #v(0.35em)
  #body
]

// End-of-paper citation block. `paper-title` is the full citable title.
#let citation-block(paper-title) = [
  #v(1.2em)
  #line(length: 100%, stroke: 0.5pt + rule-gray)
  #v(0.5em)
  #set text(size: 8pt, fill: gray-soft)
  #set par(justify: true)
  *Citation.* Galappatti, K. (2026). _#paper-title._ AEGIS Labs, Adversarix, Inc.
  #link("https://github.com/Adversarix/aegis-labs")[github.com/Adversarix/aegis-labs] \
  This whitepaper is released for public reference and citation. Reproduction in
  whole or in part requires attribution. No rights are granted to the underlying
  platform software or its implementation.
]

#let whitepaper(
  title: "",
  subtitle: "",
  version: "",
  date: "",
  platform: "Adversarix Threat Intelligence Platform",
  kicker: "SECURITY RESEARCH",
  tiles: (),
  body,
) = {
  set document(title: title + ": " + subtitle, author: "Adversarix, Inc.")
  set text(font: "Helvetica Neue", size: 9.5pt, fill: ink)
  set par(justify: true, leading: 0.62em, spacing: 1.0em)

  // ---------- cover ----------
  page(paper: "a4", fill: navy, margin: 0pt, header: none, footer: none)[
    #set par(justify: false)
    #place(left + top, rect(width: 9pt, height: 100%, fill: teal))
    #pad(left: 2.4cm, right: 2.0cm, top: 1.7cm, bottom: 1.5cm)[
      #align(right)[
        #text(fill: teal-bright, weight: "bold", size: 12.5pt, tracking: 3pt)[ADVERSARIX] \
        #text(fill: gray-cover, size: 9pt)[Research Whitepaper]
      ]
      #v(6.4cm)
      #text(fill: orange, weight: "bold", size: 10.5pt, tracking: 2.2pt)[#kicker]
      #v(1.0cm)
      #text(fill: white, size: 26pt)[#title]
      #v(0.15cm)
      #text(fill: teal-bright, size: 16.5pt)[#subtitle]
      #v(0.55cm)
      #line(length: 100%, stroke: 2pt + orange)
      #v(0.3cm)
      #text(fill: gray-cover, size: 9pt)[
        #platform \
        Version #version #h(0.7em) | #h(0.7em) #date
      ]
      #v(1.1cm)
      #grid(
        columns: tiles.len() * (1fr,),
        gutter: 14pt,
        ..tiles.map(t => rect(fill: navy-tile, inset: 13pt, width: 100%, height: 2.5cm)[
          #text(fill: teal-bright, size: 15.5pt, weight: "medium")[#t.at(0)]
          #v(0.45em)
          #par(justify: true)[#text(fill: gray-soft, size: 7.5pt)[#t.at(1)]]
        ]),
      )
    ]
    #place(bottom, dy: -1.2cm)[
      #pad(left: 2.4cm, right: 2.0cm)[
        #line(length: 100%, stroke: 0.5pt + rgb("#37474f"))
        #v(0.25cm)
        #text(fill: gray-soft, size: 7.5pt)[© 2026 Adversarix, Inc. All rights reserved. #h(0.6em) | #h(0.6em) adversarix.com]
      ]
    ]
  ]

  // ---------- body pages ----------
  set page(
    paper: "a4",
    margin: (left: 2.15cm, right: 2.15cm, top: 2.5cm, bottom: 2.4cm),
    header: [
      #set text(size: 7.5pt, fill: gray-soft)
      #title #h(1fr) Adversarix Research | 2026
      #v(-0.55em)
      #line(length: 100%, stroke: 0.9pt + navy)
    ],
    footer: [
      #line(length: 100%, stroke: 0.5pt + rule-gray)
      #v(-0.35em)
      #set text(size: 7.5pt, fill: gray-soft)
      © 2026 Adversarix, Inc. All rights reserved. | adversarix.com
      #h(1fr)
      #context [Page #counter(page).display()]
    ],
  )

  set heading(numbering: "1.1")
  show heading.where(level: 1): it => {
    block(above: 1.9em, below: 0.1em)[
      #text(size: 17.5pt, weight: "medium")[
        #text(fill: teal)[#counter(heading).display("1.")]
        #h(0.35em)
        #text(fill: heading-ink)[#it.body]
      ]
    ]
    block(above: 1.1em, below: 1.2em)[#line(length: 100%, stroke: 0.5pt + rule-gray)]
  }
  show heading.where(level: 2): it => {
    block(above: 1.5em, below: 0.7em)[
      #text(size: 11pt, weight: "medium", fill: teal)[
        #counter(heading).display("1.1")
        #h(0.4em)
        #it.body
      ]
    ]
  }

  set table(
    inset: (x: 10pt, y: 8pt),
    stroke: (x, y) => if y > 1 { (top: 0.5pt + rule-gray) },
    fill: (x, y) => if y == 0 { table-header },
  )
  show table.cell.where(y: 0): set text(fill: white, weight: "bold", size: 8.5pt)
  show table.cell: set text(size: 8.5pt)
  show table: t => block(stroke: 0.5pt + rule-gray, width: 100%)[
    #show table.cell.where(y: 0): set text(fill: white, weight: "bold", size: 8.5pt)
    #t
  ]

  body
}

// Table of contents in the house style: no dots, no page numbers,
// level-2 entries teal and indented.
#let toc() = {
  text(size: 20pt, weight: "medium", fill: heading-ink)[Table of Contents]
  v(0.5cm)
  line(length: 100%, stroke: 0.5pt + rule-gray)
  v(0.35cm)
  context {
    for hd in query(heading) {
      if hd.level == 1 {
        block(above: 0.95em, below: 0.3em)[
          #text(size: 10.5pt, fill: heading-ink)[
            #numbering("1", ..counter(heading).at(hd.location())) #h(0.45em) #hd.body
          ]
        ]
      } else if hd.level == 2 {
        block(above: 0.25em, below: 0.25em)[
          #h(1.1em)
          #text(size: 8.5pt, fill: teal)[
            #numbering("1.1", ..counter(heading).at(hd.location())) #h(0.4em) #hd.body
          ]
        ]
      }
    }
  }
  pagebreak()
}
