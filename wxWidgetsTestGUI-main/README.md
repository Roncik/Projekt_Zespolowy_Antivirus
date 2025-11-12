# Dolaczenie plikow biblioteki wxWidgets w visual studio 2022

metoda build from source

## sources download:
https://www.wxwidgets.org/downloads/

## nastepnie:
- ustawic win11 user env variable WXWIN: [sciezka_do_katalogu_gdzie_wypakowane_pliki_source]
- zbudowac solution w vs 2022, plik: wx_vc17.sln - np domyslnie w debugu i static
- dodanie w projekcie uzywajacym wxwidgets wxwidgets.props do properties w taki sposob:
	"If you use MSVS for building your project, simply add wxwidgets.props property sheet to (all) your project(s) using wxWidgets by using "View|Property Manager" menu 	item to open the property manager window and then selecting "Add Existing Property Sheet..." from the context menu in this window.
	
	If you've created a new empty project (i.e. chose "Empty Project" in the "Create a new project" window shown by MSVS rather than "Windows Desktop"), you need to change 	"Linker|System|SubSystem" in the project properties to "Windows", from the default "Console". You don't need to do anything else."