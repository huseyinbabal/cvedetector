package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const php = `id: php
name: "PHP"
images:
  - docker.io/library/php
nvd:
  cpes: [cpe:2.3:a:php:php]
testTags:
  "8.3.14-fpm-alpine": "8.3.14"
  "fpm": ""
`

func write(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoad(t *testing.T) {
	c, err := Load(write(t, map[string]string{"php.yaml": php, "README.md": "ignored"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Products) != 1 || c.Products[0].ID != "php" || !strings.HasSuffix(c.File("php"), "php.yaml") {
		t.Fatalf("%+v", c.Products)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]struct {
		files map[string]string
		want  string
	}{
		"id/file mismatch": {map[string]string{"ruby.yaml": php}, "must match the file name"},
		"wrong test tag": {map[string]string{"php.yaml": strings.Replace(php, `"8.3.14-fpm-alpine": "8.3.14"`, `"8.3.14-fpm-alpine": "8.3"`, 1)},
			`gives version "8.3.14", expected "8.3"`},
		"no registry":     {map[string]string{"php.yaml": strings.Replace(php, "docker.io/library/php", "library/php", 1)}, "must start with its registry"},
		"tag in image":    {map[string]string{"php.yaml": strings.Replace(php, "docker.io/library/php", "docker.io/library/php:8", 1)}, "without tag"},
		"duplicate image": {map[string]string{"php.yaml": php, "php2.yaml": strings.Replace(php, "id: php", "id: php2", 1)}, "already mapped"},
		"no test tags":    {map[string]string{"php.yaml": php[:strings.Index(php, "testTags:")]}, "testTags is required"},
		"unknown field":   {map[string]string{"php.yaml": php + "imgaes: []\n"}, "unknown field"},
	}
	for name, tt := range tests {
		_, err := Load(write(t, tt.files))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want %q", name, err, tt.want)
		}
	}
}
