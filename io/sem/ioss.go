package sem

type IOSS interface {
	StoreQuery(args ...interface{}) (string, error)
	LoadQuery(args ...interface{}) (string, error)
}
