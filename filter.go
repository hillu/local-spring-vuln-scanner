package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

func IsVulnerableClass(buf []byte, filename string, v Vulnerabilities) *FileInfo {
	hasher := sha256.New()
	io.Copy(hasher, bytes.NewBuffer(buf))
	sum := hex.EncodeToString(hasher.Sum(nil))

	if info, ok := vulnVersions[sum]; ok {
		if info.Vulnerabilities&v != 0 {
			return &info
		}
	}

	return nil
}

type FileInfo struct {
	Version  string
	Filename string
	Vulnerabilities
}

var vulnVersions = map[string]FileInfo{
	// 	"hash": FileInfo{
	// 		"description", "filename.class", CVE_something},

	"e16972f0533681b0ff4987cda98f34f5067b482ca61d2868e34e3c4d82781fb1": FileInfo{
		"spring 4.0.0", "CachedIntrospectionResults.class", CVE_2022_22965},

	"0591c411a21147008fb83cc5e241ed921b271438dac99479da5c0ca3bb1b40f2": FileInfo{
		"spring 4.0.1", "CachedIntrospectionResults.class", CVE_2022_22965},

	"e25682d908e833998ea36ad169a1042241fd228437ebc4e696c97f9972ffccef": FileInfo{
		"spring 4.0.2-4.0.5", "CachedIntrospectionResults.class", CVE_2022_22965},

	"cdb9558412a80c0d6c320b5a7d42eb1153fa32243277e688a2bab34e9b7191e9": FileInfo{
		"spring 4.0.6-4.0.9", "CachedIntrospectionResults.class", CVE_2022_22965},

	"7214730c8f62485edf9c550e2cd60062aaea92efc20963993df9551ad3d76fd5": FileInfo{
		"spring 4.1.0", "CachedIntrospectionResults.class", CVE_2022_22965},

	"c7a74b98d46a7799bb0946c06777c7c495919a9b6862454e58cdaf21765f6989": FileInfo{
		"spring 4.1.1-4.1.9", "CachedIntrospectionResults.class", CVE_2022_22965},

	"1210d06d77e47e9bdb5e657c8cc58081ded09e48d25ce7d2ef16697e07549caf": FileInfo{
		"spring 4.2.0-4.2.7", "CachedIntrospectionResults.class", CVE_2022_22965},

	"0f2f9a511f22bacaf8df52a4fa7c80b04072043b69205945c61ef98722188d99": FileInfo{
		"spring 4.2.8-4.2.9", "CachedIntrospectionResults.class", CVE_2022_22965},

	"03c8db6bb825f217ebf7a2718e78ac2edf2962db28b4a610a36366a916d13c15": FileInfo{
		"spring 4.3.0-4.3.2", "CachedIntrospectionResults.class", CVE_2022_22965},

	"68bf5bbaf38cabc0b7bc54d56e26e78e5e9254091cb66a78d2eb8e29a876bd6c": FileInfo{
		"spring 4.3.3-4.3.13", "CachedIntrospectionResults.class", CVE_2022_22965},

	"1592a968c8cd22afedef8d430ba20db359a956815ec95520805914931489af24": FileInfo{
		"spring 4.3.14-4.3.27", "CachedIntrospectionResults.class", CVE_2022_22965},

	"4a91519d64e3ad5ecab3e1cefbc2e175c5941e8230d8ce54de7b887338d02d84": FileInfo{
		"spring 4.3.28-4.3.30", "CachedIntrospectionResults.class", CVE_2022_22965},

	"38a47d4367cd76b957de813b8066f5ee19b8a450b4b38acdaca713cf43db4080": FileInfo{
		"spring 5.0.0-5.0.2", "CachedIntrospectionResults.class", CVE_2022_22965},

	"20ad82e25bab117d4c804e0648164841067781cc41e7b9e6f485e4d11073a485": FileInfo{
		"spring 5.0.3-5.0.4", "CachedIntrospectionResults.class", CVE_2022_22965},

	"0726931727f081adc18f4cc8a9e12d1bc1bd8d489887bb6de1c1818d59086da3": FileInfo{
		"spring 5.0.5-5.0.7", "CachedIntrospectionResults.class", CVE_2022_22965},

	"417fd370ca02fbe0a86c28d2bbe768c104a02e6fd50de31770c2df4f790e59ea": FileInfo{
		"spring 5.0.8-5.0.11", "CachedIntrospectionResults.class", CVE_2022_22965},

	"c16dab0423510596a45160f09315bb432d655fd9abd35b88e9f9de833f6dda13": FileInfo{
		"spring 5.1.1-5.1.5", "CachedIntrospectionResults.class", CVE_2022_22965},

	"005d47197459ab4ef0945031c4096dab6f47ac87745772b4333c47ceb0b2601b": FileInfo{
		"spring 5.1.6-5.2.2", "CachedIntrospectionResults.class", CVE_2022_22965},

	"82940fd349b672b2a341f2b283144eb6000b98b46603987078036a1e14f8c3dd": FileInfo{
		"spring 5.2.3-5.2.6", "CachedIntrospectionResults.class ", CVE_2022_22965},

	"85592077b7e9066793b345cb203252a6934e16da49c9c2b2aa83c4b7fbcfb91c": FileInfo{
		"spring 5.2.7-5.2.8", "CachedIntrospectionResults.class ", CVE_2022_22965},

	"54c008aed433118feaa154f8441c4c8dc44b035ac34fb495446a4b23dd700e2a": FileInfo{
		"spring 5.2.9-5.2.10", "CachedIntrospectionResults.class ", CVE_2022_22965},

	"df420f4867849871af01edaf003e95377661ddd9012da38ffeed9fa32260e288": FileInfo{
		"spring 5.2.20.RELEASE", "CachedIntrospectionResults.class ", 0},

	"f0b1dd9f37af5f29e92a7eb0f9891ec7c077ee70252b68b02a749382a4466922": FileInfo{
		"spring 5.3.0-5.3.17", "CachedIntrospectionResults.class ", CVE_2022_22965},

	"1e40398b6fd070af5b6a75cc6329c1f3c897745b7a1b5f686e893066d0b7c61b": FileInfo{
		"spring 5.3.18", "CachedIntrospectionResults.class ", 0},
}
