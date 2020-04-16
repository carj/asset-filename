# asset-filename
Copy the first bitstream in an asset into the description field

This script will find all the assets in a folder and for each asset search through the content for the first bitstream entity within the first representation.
The bitstream file name will be set on the asset description field.

The script uses the Preservica v6 Entity API and its controlled from a properties file.


```
[Section]
parent.folder=
server.name=
user.username=
user.password=
user.tenant=
```

The reference of the parent folder containing the assets to be updated.
```
parent.folder=cff121a7-f76a-4e21-93fb-2a8f9f95761c
```


The Preservica server name
```
user.domain=eu.preservica.com
```

The Preservica tenant your user account belongs to
```
user.tenant=TENANT
```

Your Preservica account username
```
user.username=test@test.com
```

Your Preservica account password
```
user.password=xyz12345
```

