package radius

import "testing"

func TestEqual(t *testing.T) {
	cases := []struct {
		first    Attributes
		second   Attributes
		expected bool
	}{
		// Checking that something is indeed equal.
		{Attributes{UserName: []byte("example")}, Attributes{UserName: []byte("example")}, true},
		// Check that it is not equal because of different field.
		{Attributes{UserName: []byte("example")}, Attributes{UserPassword: []byte("example")}, false},
		// Check not equal because field values do not match, but are same length.
		{Attributes{UserName: []byte("example")}, Attributes{UserName: []byte("exampll")}, false},
		// Check not equal, but same length.
		{Attributes{UserName: []byte("example")}, Attributes{UserName: []byte("examplee")}, false},
		// Check equality on Attributes with multiple fields.
		{Attributes{UserName: []byte("example"), UserPassword: []byte("")}, Attributes{UserName: []byte("example"), UserPassword: []byte("")}, true},
	}

	for test, c := range cases {
		got := c.first.Equal(c.second)

		if got != c.expected {
			t.Errorf("Test %d first.Equal(second) == %t, want %X", test, c.expected, got)
		}
	}

}

func TestAdd(t *testing.T) {

	cases := []struct {
		first     Attributes
		key       Attribute
		value     []byte
		expected  Attributes
		overwrite bool
	}{
		// Checks that an attribute is added to an empty Attribute list.
		{Attributes{}, UserName, []byte("example"), Attributes{UserName: []byte("example")}, false},
		// Checks that a new field is added to an Attribute list containing something.
		{Attributes{UserName: []byte("example")}, UserPassword, []byte("mypass"), Attributes{UserName: []byte("example"), UserPassword: []byte("mypass")}, false},
		// Checks that an overwrite of an existing value works correctly.
		{Attributes{UserName: []byte("example")}, UserName, []byte("myuser"), Attributes{UserName: []byte("myuser")}, true},
	}

	for test, c := range cases {
		got := c.first.Add(c.key, c.value)

		if c.first.Equal(c.expected) != true {
			t.Errorf("Test %d first.Add(%d, %X) is not as expected!", test, c.key, c.value)
		}
		if got != c.overwrite {
			t.Errorf("Test %d first.Add(%d, %X) = %t, expected %t ", test, c.key, c.value, got, c.overwrite)
		}
	}
}
