/**
 * Copyright (C) 2007 Saikat Guha <saikat@cs.cornell.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "check-sternd.h"

int main(int argc, char **argv)
{
    int num_failed, num_run, i, num;
    SRunner *runner;
    TestResult **results;
    int verbose = 0;

    if (argc > 1 && strcmp(argv[1], "-v") == 0)
        verbose = 1;

    runner = srunner_create(check_stund());
    srunner_add_suite(runner, check_turnd());
    srunner_run_all(runner, CK_MINIMAL);

    num_run = srunner_ntests_run(runner);
    num_failed = srunner_ntests_failed(runner);

    if (verbose) {
        results = srunner_results(runner);
        num = num_run;
    } else {
        results = srunner_failures(runner);
        num = num_failed;
    }
    for (i = 0; i < num; i++) {
        printf("%s%s%s\n",
               tr_rtype(results[i]) == CK_PASS ? "[32m" :
               tr_rtype(results[i]) == CK_FAILURE ? "[31m" :
               tr_rtype(results[i]) == CK_ERROR ? "[31m" : "",
               tr_str(results[i]),
               "[0m");
    }
    free(results);

    srunner_free(runner);

    return num_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

