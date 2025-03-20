#include <iostream>
#include <vector>
#include <gmpxx.h>
#include <cassert>

using BigInt = mpz_class;

std::vector<std::vector<BigInt>> gramSchmidt(const std::vector<std::vector<BigInt>> &basis)
{
    size_t n = basis.size();
    size_t m = basis[0].size();
    std::vector<std::vector<BigInt>> orthogonalBasis(n, std::vector<BigInt>(m, 0));

    for (size_t i = 0; i < n; ++i) {
        orthogonalBasis[i] = basis[i];
        for (size_t j = 0; j < i; ++j) {
            BigInt dotProduct = 0;
            BigInt normSquared = 0;

            for (size_t k = 0; k < m; ++k) {
                dotProduct += basis[i][k] * orthogonalBasis[j][k];
                normSquared += orthogonalBasis[j][k] * orthogonalBasis[j][k];
            }

            BigInt projectionFactor = dotProduct / normSquared;
            for (size_t k = 0; k < m; ++k) {
                orthogonalBasis[i][k] -= projectionFactor * orthogonalBasis[j][k];
            }
        }
    }
    return orthogonalBasis;
}

void lllAlgorithm(std::vector<std::vector<BigInt>> &basis, double delta = 0.75)
{
    assert(delta > 0.5 && delta <= 1.0);

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

                BigInt mu = dotProduct / normSquared;
                BigInt roundMu;
                BigInt half = 1;
                half /= 2;

                if (mu > 0) {
                    roundMu = mu + half;
                } else {
                    roundMu = mu - half;
                }

                for (size_t k = 0; k < m; ++k) {
                    basis[i][k] -= roundMu * basis[j][k];
                }
            }

            BigInt lhs = 0, rhs = 0;
            BigInt mu_cond = 0, mu_cond_squared = 0;

            for (size_t k = 0; k < m; ++k) {
                lhs += orthogonalBasis[i][k] * orthogonalBasis[i][k];
                rhs += orthogonalBasis[i - 1][k] * orthogonalBasis[i - 1][k];
                mu_cond += basis[i][k] * orthogonalBasis[i - 1][k];
            }
            mu_cond /= rhs;
            mu_cond_squared = mu_cond * mu_cond;
            rhs *= (delta - mu_cond_squared);

            if (lhs < rhs) {
                std::swap(basis[i - 1], basis[i]);
                changed = true;
                break;
            }
        }

        if (!changed) {
            break;
        }
    }
}

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
    printf("here\n");
    std::vector<std::vector<BigInt>> basis = {
        { 1, 2, 3, 4 },
        { 3, 1, 4, 1 },
        { 5, 9, 2, 6 },
        { 5, 3, 5, 8 }
    };
    printf("here\n");

    std::cout << "Original Basis:" << std::endl;
    printMatrix(basis);

    lllAlgorithm(basis);

    std::cout << "Reduced Basis:" << std::endl;
    printMatrix(basis);

    return 0;
}