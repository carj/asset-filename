# asset-filename
Copy the first bitstream in an asset into the description field

This script will find all the assets in a folder and for each asset search through the content for the first bitstream entity within the first representation.
The bitstream file name will be set on the asset description field.

The script uses the Preservica v6 Entity API and its controlled from a properties file.

`
[OptionalAPIUploadSection]
user.domain=
user.username=
user.password=
user.tenant=
`



