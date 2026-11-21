// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package artifact

// Detectors is the built-in known-software table. To add software, append
// an entry: match by base name (and optionally trailing path components),
// give the fixed version arguments and a parse rule for their output, and at
// least one static rule for when the command cannot be run. Patterns are
// checked against captured real outputs in testdata/versions.txtar; add the
// output of the new software there too.
//
// Go binaries are never executed, so detectors for Go software (Docker,
// containerd) have static rules only.
var Detectors = []*Detector{
	{
		ID:    "openjdk",
		Name:  "openjdk",
		Names: []string{"java"},
		Paths: []string{"bin/java"},
		// The heap and reservation flags let the JVM start under the
		// address space limit; they do not change the output.
		Exec: []string{"-XX:+IgnoreUnrecognizedVMOptions", "-Xmx64m", "-XX:CompressedClassSpaceSize=64m",
			"-XX:ReservedCodeCacheSize=32m", "-XX:-UsePerfData", "-version"},
		Env:            []EnvVar{{Name: "JAVA_HOME", Up: 2}},
		AddressSpaceMB: 4096,
		Parse: []Rule{
			{Pattern: re(`(?m)^openjdk version "([^"]+)"`)},
			{Pattern: re(`(?m)^java version "([^"]+)"`), Name: "jdk", PURL: "pkg:generic/oracle/jdk@{version}",
				CPE: "cpe:2.3:a:oracle:jdk:{version}:*:*:*:*:*:*:*"},
		},
		Static: []StaticRule{
			{File: "../release", Rules: []Rule{{Pattern: re(`(?m)^JAVA_VERSION="([^"]+)"`)}}},
			{File: "../../release", Rules: []Rule{{Pattern: re(`(?m)^JAVA_VERSION="([^"]+)"`)}}},
		},
		PURL: "pkg:generic/openjdk@{version}",
		CPE:  "cpe:2.3:a:oracle:openjdk:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "nodejs",
		Name:  "node",
		Names: []string{"node", "nodejs"},
		Exec:  []string{"--version"},
		Parse: []Rule{{Pattern: re(`(?m)^v(\d+\.\d+\.\d+)\s*$`)}},
		Static: []StaticRule{
			{Rules: []Rule{{Pattern: re(`nodejs\.org/download/release/v(\d+\.\d+\.\d+)/`)}}},
		},
		PURL: "pkg:generic/node@{version}",
		CPE:  "cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "php",
		Name:  "php",
		Names: []string{"php", "php[0-9]*", "php-cgi*"},
		Exec:  []string{"-v"},
		Parse: []Rule{{Pattern: re(`(?m)^PHP (\d+\.\d+\.\d+[^\s]*) \(`)}},
		Static: []StaticRule{
			{Rules: []Rule{{Pattern: re(`X-Powered-By: PHP/(\d+\.\d+\.\d+)`)}}},
		},
		PURL: "pkg:generic/php@{version}",
		CPE:  "cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "php-fpm",
		Name:  "php",
		Names: []string{"php-fpm*"},
		Exec:  []string{"-v"},
		Parse: []Rule{{Pattern: re(`(?m)^PHP (\d+\.\d+\.\d+[^\s]*) \(fpm`)}},
		Static: []StaticRule{
			{Rules: []Rule{{Pattern: re(`X-Powered-By: PHP/(\d+\.\d+\.\d+)`)}}},
		},
		PURL: "pkg:generic/php@{version}",
		CPE:  "cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "python",
		Name:  "python",
		Names: []string{"python", "python2", "python3", "python2.[0-9]*", "python3.[0-9]*"},
		Exec:  []string{"--version"},
		Parse: []Rule{{Pattern: re(`(?m)^Python (\d+\.\d+\.\d+\S*)`)}},
		Static: []StaticRule{
			// PY_VERSION is stored right before the Py_GetVersion format.
			{Rules: []Rule{{Pattern: re(`\x00(\d+\.\d+\.\d+(?:[abc]|rc)?\d*)\x00%\.80s \(%\.80s\) %\.80s`)}}},
			{File: "../lib/libpython[23].*.so*", Rules: []Rule{{Pattern: re(`\x00(\d+\.\d+\.\d+(?:[abc]|rc)?\d*)\x00%\.80s \(%\.80s\) %\.80s`)}}},
			{File: "../lib/*/libpython[23].*.so*", Rules: []Rule{{Pattern: re(`\x00(\d+\.\d+\.\d+(?:[abc]|rc)?\d*)\x00%\.80s \(%\.80s\) %\.80s`)}}},
		},
		PURL: "pkg:generic/python@{version}",
		CPE:  "cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "ruby",
		Name:  "ruby",
		Names: []string{"ruby", "ruby[0-9]*"},
		Exec:  []string{"--version"},
		Parse: []Rule{{Pattern: re(`(?m)^ruby (\d+\.\d+\.\d+)`)}},
		Static: []StaticRule{
			{Rules: []Rule{{Pattern: re(`ruby (\d+\.\d+\.\d+)(?:p\d+)? \(\d{4}-\d\d-\d\d`)}}},
			{File: "../lib/libruby.so*", Rules: []Rule{{Pattern: re(`ruby (\d+\.\d+\.\d+)(?:p\d+)? \(\d{4}-\d\d-\d\d`)}}},
			{File: "../lib/*/libruby*.so*", Rules: []Rule{{Pattern: re(`ruby (\d+\.\d+\.\d+)(?:p\d+)? \(\d{4}-\d\d-\d\d`)}}},
		},
		PURL: "pkg:generic/ruby@{version}",
		CPE:  "cpe:2.3:a:ruby-lang:ruby:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "perl",
		Name:  "perl",
		Names: []string{"perl", "perl5*"},
		Exec:  []string{"-v"},
		Parse: []Rule{{Pattern: re(`This is perl \d+, version \d+, subversion \d+ \(v(\d+\.\d+\.\d+)\)`)}},
		Static: []StaticRule{
			{Rules: []Rule{{Pattern: re(`is not supported by Perl (5\.\d+\.\d+)`)}, {Pattern: re(`/perl5/(5\.\d+\.\d+)/`)}}},
			{File: "../lib/*/libperl.so*", Rules: []Rule{{Pattern: re(`is not supported by Perl (5\.\d+\.\d+)`)}}},
		},
		PURL: "pkg:generic/perl@{version}",
		CPE:  "cpe:2.3:a:perl:perl:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "nginx",
		Name:  "nginx",
		Names: []string{"nginx"},
		Exec:  []string{"-v"},
		Parse: []Rule{
			{Pattern: re(`nginx version: nginx/(\d+\.\d+\.\d+)`)},
			{Pattern: re(`nginx version: openresty/(\d+\.\d+\.\d+(?:\.\d+)?)`), Name: "openresty",
				PURL: "pkg:generic/openresty@{version}", CPE: "cpe:2.3:a:openresty:openresty:{version}:*:*:*:*:*:*:*"},
		},
		Static: []StaticRule{
			{Rules: []Rule{
				{Pattern: re(`nginx version: nginx/(\d+\.\d+\.\d+)`)},
				{Pattern: re(`nginx version: openresty/(\d+\.\d+\.\d+(?:\.\d+)?)`), Name: "openresty",
					PURL: "pkg:generic/openresty@{version}", CPE: "cpe:2.3:a:openresty:openresty:{version}:*:*:*:*:*:*:*"},
			}},
		},
		PURL: "pkg:generic/nginx@{version}",
		CPE:  "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "httpd",
		Name:  "httpd",
		Names: []string{"httpd", "apache2"},
		Exec:  []string{"-v"},
		Parse: []Rule{{Pattern: re(`Server version: Apache/(\d+\.\d+\.\d+)`)}},
		Static: []StaticRule{
			{Rules: []Rule{{Pattern: re(`\x00Apache/(\d+\.\d+\.\d+)`)}}},
		},
		PURL: "pkg:generic/apache/httpd@{version}",
		CPE:  "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "redis",
		Name:  "redis",
		Names: []string{"redis-server"},
		Exec:  []string{"--version"},
		Parse: []Rule{{Pattern: re(`Redis server v=(\d+\.\d+\.\d+)`)}},
		Static: []StaticRule{
			// REDIS_VERSION followed by the build id (host name and time).
			{Rules: []Rule{{Pattern: re(`\x00(\d+\.\d+\.\d+)[^\x00]{1,128}-\d{9,}\x00`)}}},
		},
		PURL: "pkg:generic/redis@{version}",
		CPE:  "cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "postgresql",
		Name:  "postgresql",
		Names: []string{"postgres"},
		Exec:  []string{"--version"},
		Parse: []Rule{{Pattern: re(`\(PostgreSQL\) (\d+(?:\.\d+)+)`)}},
		Static: []StaticRule{
			{Rules: []Rule{{Pattern: re(`PostgreSQL (\d+(?:\.\d+)+)(?: \([^)\x00]*\))? on `)}}},
		},
		PURL: "pkg:generic/postgresql@{version}",
		CPE:  "cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "mysql",
		Name:  "mysql",
		Names: []string{"mysqld", "mariadbd"},
		Exec:  []string{"--version"},
		Parse: []Rule{
			{Pattern: re(`Ver (\d+\.\d+\.\d+)-MariaDB`), Name: "mariadb",
				PURL: "pkg:generic/mariadb@{version}", CPE: "cpe:2.3:a:mariadb:mariadb:{version}:*:*:*:*:*:*:*"},
			{Pattern: re(`Ver (\d+\.\d+\.\d+)`)},
		},
		Static: []StaticRule{
			{Rules: []Rule{
				{Pattern: re(`\x00(\d+\.\d+\.\d+)-MariaDB`), Name: "mariadb",
					PURL: "pkg:generic/mariadb@{version}", CPE: "cpe:2.3:a:mariadb:mariadb:{version}:*:*:*:*:*:*:*"},
				{Pattern: re(`/mysql-(\d+\.\d+\.\d+)/`)},
			}},
		},
		PURL: "pkg:generic/mysql@{version}",
		CPE:  "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "mongodb",
		Name:  "mongodb",
		Names: []string{"mongod", "mongos"},
		Exec:  []string{"--version"},
		Parse: []Rule{{Pattern: re(`(?m)^(?:db|mongos) version v(\d+\.\d+\.\d+)`)}},
		// The version is stored as a bare string with nothing stable next
		// to it, so there is no static rule.
		PURL: "pkg:generic/mongodb@{version}",
		CPE:  "cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "openssl",
		Name:  "openssl",
		Names: []string{"openssl"},
		Exec:  []string{"version"},
		Parse: []Rule{{Pattern: re(`(?m)^OpenSSL (\d+\.\d+\.\d+[a-z]?)`)}},
		Static: []StaticRule{
			{Rules: []Rule{{Pattern: re(`OpenSSL (\d+\.\d+\.\d+[a-z]?) {1,2}\d{1,2} [A-Z][a-z]{2} \d{4}`)}}},
		},
		PURL: "pkg:generic/openssl@{version}",
		CPE:  "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:      "tomcat",
		Name:    "tomcat",
		Names:   []string{"catalina.jar"},
		Paths:   []string{"lib/catalina.jar", "server/lib/catalina.jar"},
		Archive: true,
		Static: []StaticRule{
			{Entry: "META-INF/MANIFEST.MF", Rules: []Rule{{Pattern: re(`(?m)^Implementation-Version: *(\d+\.\d+\.\d+\S*)`)}}},
			{File: "../RELEASE-NOTES", Rules: []Rule{{Pattern: re(`Apache Tomcat Version (\d+\.\d+\.\d+\S*)`)}}},
		},
		PURL: "pkg:maven/org.apache.tomcat/tomcat@{version}",
		CPE:  "cpe:2.3:a:apache:tomcat:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "dockerd",
		Name:  "docker",
		Names: []string{"dockerd"},
		Static: []StaticRule{
			{BuildSetting: "-ldflags", Rules: []Rule{{Pattern: re(`dockerversion\.Version=([0-9][^"\\\s]*)`)}}},
			{GoMain: true},
		},
		PURL: "pkg:golang/github.com/docker/docker@v{version}",
		CPE:  "cpe:2.3:a:docker:docker:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "docker-cli",
		Name:  "docker-cli",
		Names: []string{"docker"},
		Static: []StaticRule{
			{BuildSetting: "-ldflags", Rules: []Rule{{Pattern: re(`cli/version\.Version=([0-9][^"\\\s]*)`)}}},
			{GoMain: true},
		},
		PURL: "pkg:golang/github.com/docker/cli@v{version}",
		CPE:  "cpe:2.3:a:docker:docker:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "containerd",
		Name:  "containerd",
		Names: []string{"containerd", "containerd-shim*", "ctr"},
		Static: []StaticRule{
			{BuildSetting: "-ldflags", Rules: []Rule{{Pattern: re(`containerd(?:/v2)?/version\.Version=v?([0-9][^"\\\s]*)`)}}},
			{GoMain: true},
		},
		PURL: "pkg:golang/github.com/containerd/containerd@v{version}",
		CPE:  "cpe:2.3:a:linuxfoundation:containerd:{version}:*:*:*:*:*:*:*",
	},
	{
		ID:    "runc",
		Name:  "runc",
		Names: []string{"runc"},
		Static: []StaticRule{
			{GoMain: true},
			{BuildSetting: "-ldflags", Rules: []Rule{{Pattern: re(`main\.version=v?([0-9][^"\\\s]*)`)}}},
		},
		PURL: "pkg:golang/github.com/opencontainers/runc@v{version}",
		CPE:  "cpe:2.3:a:linuxfoundation:runc:{version}:*:*:*:*:*:*:*",
	},
}
