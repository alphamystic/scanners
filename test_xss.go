package main

import(
  "github.com/alphamystic/scanners/xss"
)

func main(){
  target := xss.Target{
    Input: "tum.ac.ke",
    IsIp: false,
  }
  xss.StartScan(target)
}
