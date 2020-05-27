version 1.0

workflow foo {
  Int x
  output {
    Int y = x + 1
  }
}
