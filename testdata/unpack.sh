#!/bin/sh

for jar in *.jar; do
    version=$(echo $jar | sed -e 's/^spring-beans-\(.*\)\(.RELEASE\)*[.]jar$/\1/' )
    echo $version
    7z x -so $jar org/springframework/beans/CachedIntrospectionResults.class > CachedIntrospectionResults.class.$version
done
