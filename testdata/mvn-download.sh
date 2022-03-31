#!/bin/bash

NAME=org.springframework:spring-beans

# VERSIONS=5.3.{0..18}-RELEASE
# VERSIONS=

# 5.1.{0..11}.RELEASE
# 5.0.{0..11}.RELEASE

for version in 4.0.{0..10}.RELEASE 4.1.{0..10}.RELEASE; do
    echo "- $version"
    mvn dependency:copy -Dtransitive=false -Dartifact=$NAME:$version -DoutputDirectory=.
done
