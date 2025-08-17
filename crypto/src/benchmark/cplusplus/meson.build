#
# Copyright (c) 2024-2025 Pavel Vasin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

crypto_benchmark_sources = [
    'ajtaicommitment.cpp',
    'benchmark.cpp',
    'bfv.cpp',
    'blacklemon.cpp',
    'cyclotomicring.cpp',
    'ellipticcurve.cpp',
    'extensionfield.cpp',
    'integerring.cpp',
    'johnsonlindenstrauss.cpp',
    'latticefold.cpp',
    'pedersencommitment.cpp',
    'poseidon2.cpp',
    'primefield.cpp',
]
crypto_benchmark_includes = crypto_main_includes
crypto_benchmark_dependencies = [crypto_main_dependencies, google_benchmark_dependency]
crypto_benchmark_bin = executable(
    'crypto_benchmark',
    crypto_benchmark_sources,
    implicit_include_directories : false,
    include_directories : crypto_benchmark_includes,
    dependencies : crypto_benchmark_dependencies
)
benchmark('crypto benchmark', crypto_benchmark_bin)
