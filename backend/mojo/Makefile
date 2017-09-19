DB_USER=tippuser_test
DB_NAME=tippdb_test
all:

test:
	createdb -U $(DB_USER) $(DB_NAME)
	psql -U $(DB_USER) $(DB_NAME) < ../../sql/tipp.sql
	psql -U $(DB_USER) $(DB_NAME) < t/prepare_test.sql

	MOJO_MODE=test PERL5LIB="lib" prove t

clean:
	dropdb -U $(DB_USER) $(DB_NAME)
