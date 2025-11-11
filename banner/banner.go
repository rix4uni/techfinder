package banner

import (
	"fmt"
)

// prints the version message
const version = "v0.0.3"

func PrintVersion() {
	fmt.Printf("Current techx version %s\n", version)
}

// Prints the Colorful banner
func PrintBanner() {
	banner := `
   __               __         
  / /_ ___   _____ / /_   _  __
 / __// _ \ / ___// __ \ | |/_/
/ /_ /  __// /__ / / / /_>  <  
\__/ \___/ \___//_/ /_//_/|_|
`
	fmt.Printf("%s\n%40s\n\n", banner, "Current techx version "+version)
}
