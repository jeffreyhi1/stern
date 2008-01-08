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
#include "check-libstern.h"

int main(int argc, char **argv)
{
    int num_failed, num_run, i;
    SRunner *runner;
    TestResult **results;

    runner = srunner_create(check_parser());
    srunner_add_suite(runner, check_stun());
    srunner_run_all(runner, CK_MINIMAL);

    num_run = srunner_ntests_run(runner);
    results = srunner_results(runner);
    for (i = 0; i < num_run; i++) {
        printf("%s%s%s\n",
               tr_rtype(results[i]) == CK_PASS ? "[32m" :
               tr_rtype(results[i]) == CK_FAILURE ? "[31m" :
               tr_rtype(results[i]) == CK_ERROR ? "[31m" : "",
               tr_str(results[i]),
               "[0m");
    }

    num_failed = srunner_ntests_failed(runner);
    srunner_free(runner);

    return num_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

