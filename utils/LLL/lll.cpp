#include <iostream>
#include <vector>
#include <gmpxx.h>
#include <cmath>

#include "lll.hpp"

#define BASE (10)

mpz_class floor_mpq(const mpq_class& q) {
    mpz_class num = q.get_num();  // Get the numerator
    mpz_class denom = q.get_den();  // Get the denominator

    // Perform integer division to find the "integer part" of q
    mpz_class int_part = num / denom;

    // If q is negative and there's a remainder, we need to round down more
    if (num < 0 && num % denom != 0) {
        int_part -= 1;
    }

    // Return the floor as an mpq_class
    return int_part;
}

mpz_class round_mpq(const mpq_class& q) {
    mpz_class num = q.get_num();  // Get the floor value
    mpz_class denum = q.get_den();  // Get the fractional part
    mpz_class reminder = num % denum;
    mpz_class quationt = num / denum;
    if (reminder < 0) {
        reminder += denum;
        quationt -= 1;
    }

    // If the fractional part is >= 0.5, round up
    if (2 * reminder > denum) {
        return quationt + 1;  // Add 1 to round up
    }

    // Otherwise, return the floor value (round down)
    return quationt;
}

// Function to perform Gram-Schmidt orthogonalization on a basis of mpz_class vectors
std::vector<std::vector<mpq_class>> gramSchmidt(const std::vector<std::vector<mpz_class>>& basis) {
    size_t n = basis.size();
    size_t m = basis[0].size();
    std::vector<std::vector<mpq_class>> orthogonalBasis(n, std::vector<mpq_class>(m));

    for (size_t i = 0; i < n; ++i) {
        // Start with the current vector as the initial orthogonal basis
        for (size_t j = 0; j < m; ++j) {
            orthogonalBasis[i][j] = mpq_class(basis[i][j], 1); // Convert each mpz_class to mpq_class
        }
        for (size_t j = 0; j < i; ++j) {
            mpq_class dotProduct = 0;
            mpq_class normSquared = 0;
            for (size_t k = 0; k < m; ++k) {
                dotProduct += orthogonalBasis[i][k] * orthogonalBasis[j][k];
                normSquared += orthogonalBasis[j][k] * orthogonalBasis[j][k];
            }
            mpq_class projectionFactor = dotProduct / normSquared;
            for (size_t k = 0; k < m; ++k) {
                orthogonalBasis[i][k] -= projectionFactor * orthogonalBasis[j][k];
            }
        }
    }
    return orthogonalBasis;
}

// LLL algorithm implementation with big integers
void lllAlgorithm(std::vector<std::vector<mpz_class>>& basis, double delta) {
    size_t n = basis.size();
    size_t m = basis[0].size();

    while (true) {
        // Perform Gram-Schmidt orthogonalization
        auto orthogonalBasis = gramSchmidt(basis);
        bool changed = false;

        for (size_t i = 1; i < n; ++i) {
            // Size reduction step
            for (size_t j = i - 1; j < i; --j) {
                // Compute mu = <b[i], b*[j]> / <b*[j], b*[j]>
                mpq_class dotProduct = 0;
                for (size_t k = 0; k < m; ++k) {
                    dotProduct += basis[i][k] * orthogonalBasis[j][k];
                }
                mpq_class normSquared = 0;
                for (size_t k = 0; k < m; ++k) {
                    normSquared += orthogonalBasis[j][k] * orthogonalBasis[j][k];
                }

                mpq_class mu = dotProduct / normSquared;

                if (abs(2 * mu.get_num()) > mu.get_den()) {
                    mpz_class roundMu = round_mpq(mu);
                    for (size_t k = 0; k < m; ++k) {
                        basis[i][k] -= roundMu * basis[j][k];
                    }
                    changed = true;
                }
            }

            // Check Lovász condition
            mpq_class mu_cond = 0;
            for (size_t k = 0; k < m; ++k) {
                mu_cond += basis[i][k] * orthogonalBasis[i - 1][k];
            }
            mpq_class normSquared = 0;
            for (size_t k = 0; k < m; ++k) {
                normSquared += orthogonalBasis[i - 1][k] * orthogonalBasis[i - 1][k];
            }
            mu_cond /= normSquared;

            mpq_class lhs = 0;
            for (size_t k = 0; k < m; ++k) {
                lhs += orthogonalBasis[i][k] * orthogonalBasis[i][k];
            }

            mpq_class rhs = (delta - mu_cond * mu_cond) * normSquared;

            if (lhs < rhs) {
                // Swap basis vectors if the condition is violated
                std::swap(basis[i - 1], basis[i]);
                changed = true;
                break;
            }
        }

        if (!changed) {
            // Exit the loop if no changes were made
            break;
        }
    }
}

// Function to print a basis
void printBasis(const std::vector<std::vector<mpz_class>>& basis) {
    for (const auto& vec : basis) {
        for (const auto& value : vec) {
            std::cout << value << " ";
        }
        std::cout << std::endl;
    }
}


std::vector<std::vector<mpz_class>> convertToMpzVector(char*** string_matrix, int num_rows, const int* num_cols) {
    std::vector<std::vector<mpz_class>> result;
    for (int i = 0; i < num_rows; ++i) {
        std::vector<mpz_class> row;
        for (int j = 0; j < num_cols[i]; ++j) {
            mpz_class value(string_matrix[i][j]);
            row.push_back(value);
        }
        result.push_back(row);
    }
    return result;
}

char*** createStringMatrix(const std::vector<std::vector<mpz_class>> data) {
    char*** ans = (char***)calloc(data.size(), sizeof(char**));
    for (int i = 0; i < data.size(); ++i) {
        ans[i] = (char**)calloc(data[i].size(), sizeof(char*));
        for (int j = 0; j < data[i].size(); ++j) {
            ans[i][j] = strdup(data[i][j].get_str(BASE).c_str());
        }
    }
    return ans;
}


extern "C" char*** lll(char*** string_matrix, int num_rows, int* num_cols, double delta) {
    std::vector<std::vector<mpz_class>> input = convertToMpzVector(string_matrix, num_rows, num_cols);
    
    lllAlgorithm(input, delta);
    
    char*** ans = createStringMatrix(input);
    return ans;
}


extern "C" void free_matrix(char*** string_matrix, int num_rows, int* num_cols) {
    for (int i = 0; i < num_rows; i++) {
        for (int j = 0; j < num_cols[i]; j++) {
            free(string_matrix[i][j]);
        }
        free(string_matrix[i]);
    }
    free(string_matrix);
}
