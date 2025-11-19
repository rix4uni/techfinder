package banner

import (
	"fmt"
)

// prints the version message
const version = "v0.0.4"

func PrintVersion() {
	fmt.Printf("Current techfinder version %s\n", version)
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
	fmt.Printf("%s\n%40s\n\n", banner, "Current techfinder version "+version)
}
