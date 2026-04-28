#pragma once
//
// Canonical type aliases shared across core/.
//
// `Bytes` used to be redeclared in 19 separate headers (some at file
// scope, some in namespaces, some inside classes as `Foo::Bytes`).
// They were textually identical but primed to drift if the underlying
// representation ever changed (e.g., to `std::vector<std::byte>`).
// One include, one definition.
//

#include <cstdint>
#include <vector>

using Bytes = std::vector<uint8_t>;
