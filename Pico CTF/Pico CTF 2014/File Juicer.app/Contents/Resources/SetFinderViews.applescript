tell application "Finder"
	--This script should be saved as text. It is run on the
	--created jpg,gif and png foilders
	-- the variable posixPathAsAlias is set from FileJuicer
	set thefolder to (posixPathAsAlias)
	set fw to get container window of thefolder
	set current view of fw to icon view
	set opts to icon view options of fw
	set shows icon preview of opts to true
	set icon size of opts to 128
end tell