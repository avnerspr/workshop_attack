#include <iostream>
#include <vector>
#include <gmpxx.h>

using BigInt = mpz_class;
using BigRat = mpq_class;

/**
 * Performs Gram-Schmidt orthogonalization using big integers.
 */
std::vector<std::vector<BigInt>> gramSchmidt(const std::vector<std::vector<BigInt>> &basis)
{
    size_t n = basis.size();
    size_t m = basis[0].size();
    std::vector<std::vector<BigInt>> orthogonalBasis(n, std::vector<BigInt>(m));

    for (size_t i = 0; i < n; ++i) {
        orthogonalBasis[i] = basis[i];
        for (size_t j = 0; j < i; ++j) {
            BigInt dotProduct = 0;
            BigInt normSquared = 0;
            for (size_t k = 0; k < m; ++k) {
                dotProduct += basis[i][k] * orthogonalBasis[j][k];
                normSquared += orthogonalBasis[j][k] * orthogonalBasis[j][k];
            }
            if (normSquared != 0) {
                BigRat projectionFactor(dotProduct, normSquared);
                for (size_t k = 0; k < m; ++k) {
                    orthogonalBasis[i][k] -= projectionFactor.get_num() / projectionFactor.get_den() * orthogonalBasis[j][k];
                }
            }
        }
    }
    return orthogonalBasis;
}

/**
 * Implements the LLL algorithm using big integers.
 */
void lllAlgorithm(std::vector<std::vector<BigInt>> &basis, BigRat delta = BigRat(3, 4))
{
    size_t n = basis.size();
    size_t m = basis[0].size();

    while (true) {
        auto orthogonalBasis = gramSchmidt(basis);
        bool changed = false;

        for (size_t i = 1; i < n; ++i) {
            for (size_t j = i - 1; j < i; --j) {
                BigInt dotProduct = 0;
                BigInt normSquared = 0;
                for (size_t k = 0; k < m; ++k) {
                    dotProduct += basis[i][k] * orthogonalBasis[j][k];
                    normSquared += orthogonalBasis[j][k] * orthogonalBasis[j][k];
                }
                if (normSquared != 0) {
                    BigRat mu(dotProduct, normSquared);
                    if (abs(mu.get_num()) > mu.get_den() / 2) {
                        BigInt roundMu = (mu.get_num() + mu.get_den() / 2) / mu.get_den();
                        for (size_t k = 0; k < m; ++k) {
                            basis[i][k] -= roundMu * basis[j][k];
                        }
                    }
                }
            }

            BigInt lhs = 0;
            BigInt rhs = 0;
            for (size_t k = 0; k < m; ++k) {
                lhs += orthogonalBasis[i][k] * orthogonalBasis[i][k];
                rhs += orthogonalBasis[i - 1][k] * orthogonalBasis[i - 1][k];
            }
            rhs *= delta.get_num();
            rhs /= delta.get_den();

            if (lhs < rhs) {
                std::swap(basis[i - 1], basis[i]);
                changed = true;
                break;
            }
        }
        if (!changed)
            break;
    }
}

/**
 * Utility function to print a matrix of BigInts.
 */
void printMatrix(const std::vector<std::vector<BigInt>> &matrix)
{
    for (const auto &row : matrix) {
        for (const auto &value : row) {
            std::cout << value << " ";
        }
        std::cout << std::endl;
    }
}

int main()
{
    std::vector<std::vector<BigInt>> basis = {
        { 1, 2, 3, 4 },
        { 3, 1, 4, 1 },
        { 5, 9, 2, 6 },
        { 5, 3, 5, 8 }
    };

    std::cout << "Original Basis:" << std::endl;
    printMatrix(basis);

    lllAlgorithm(basis);

    std::cout << "Reduced Basis:" << std::endl;
    printMatrix(basis);

    return 0;
}
