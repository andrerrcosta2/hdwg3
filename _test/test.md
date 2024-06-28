## 1. Run all tests inside a package
   To run all tests within a specific package, navigate to the package directory and use:
```
$ go test
```

Or you can specify the package directly from any location:

```
$ go test ./path/to/package
```

## 2. Run tests by file name

To run tests from a specific file within a package, use the -run flag followed by a regular expression pattern that matches the test names you want to run. However, to specify a file directly, you can use:

```
$ go test -run '^TestFunctionName$' ./path/to/package -v
```
Note that you can use the -v flag for verbose output to see detailed information about the test run.

## 3. Run all tests in the entire project
To run all tests across all packages in the entire project, navigate to the root of your project directory and use:

```
$ go test ./...
```

This command will recursively find and run all tests in the project.

Examples for the given test cases
Assuming your project directory structure looks something like this:

```
myproject/
  ├── prx.go
  ├── prx_test.go
  └── otherpackage/
        ├── other.go
        └── other_test.go

```

### Running tests in a specific file (prx_test.go):
To run tests from the prx_test.go file, you would typically specify the test names. Since specifying the file directly isn't supported, you need to ensure that your test functions are uniquely named or that you can target them with a pattern. For example, if your test functions are named TestHTree

```
$ cd myproject
$ go test -run '^TestHTree$'
```

### Running all tests in the entire project:

```
$ cd myproject
$ go test ./...
```