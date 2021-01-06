# editPE
edit PE file with go


```go
    
func Test (){

    // open a exe file
	file, err := ioutil.ReadFile("..\\hello.exe")
	if err != nil {
		panic(err)
	}

	p := PE{}
	p.Parse(file)

	fmt.Println(len(p.ImageSectionHeaders))

	// add a new section size is 100 byte
	p.AddSection(".new", 100)

	// save to disk
	f, err := os.Create("..\\hello2.exe")
	if err != nil {
		panic(err)
	}

	f.Write(p.raw)

    // get PE file icon
    icons, err := p.GetIcon()
   	if err != nil {
    	panic(err)
    }
    
    for k, icon := range icons {
    	f, err := os.Create(fmt.Sprintf("icon%d.ico", k))
    	if err != nil {
    		panic(err)
    	}
    	f.Write(icon)
    	f.Close()
    }

    // get dll export function
    funcs := p.GetExportFunc()

	for _, v := range funcs.EAT {
		fmt.Printf("%x \n", v.RVA)
	}

	for _, v := range funcs.FuncName {
		fmt.Printf("%s \n", v.Name)
	}
}
```