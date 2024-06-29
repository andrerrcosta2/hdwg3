/*
	André R R Costa ** github.com/andrerrcosta2
*/

package sem

type IOSS interface {
	StoreQuery(args ...interface{}) (string, error)
	LoadQuery(args ...interface{}) (string, error)
}
