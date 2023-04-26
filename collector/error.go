package collector

import "fmt"

// bucket naming string error
type errBucketName struct {
	message string
}

func newBucketNameError() *errBucketName {
	return &errBucketName{
		message: fmt.Sprintf("String doesn't match bucket naming rules and will be skipped. %s", bucketNamingRulesDescription),
	}
}

func (e *errBucketName) Error() string {
	return e.message
}

// comment string error
type errCommentString struct {
	message string
}

func newCommentStringError(message string) *errCommentString {
	return &errCommentString{
		message: message,
	}
}

func (e *errCommentString) Error() string {
	return e.message
}

// blank string error
type errBlankString struct {
	message string
}

func newBlankStringError(message string) *errBlankString {
	return &errBlankString{
		message: message,
	}
}

func (e *errBlankString) Error() string {
	return e.message
}

// directory error
type errIsDir struct {
	path string
}

func (e *errIsDir) Error() string {
	return fmt.Sprintf("'%s' is a directory", e.path)
}
