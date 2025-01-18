#include <iostream>
#include <vector>
#include <cmath>
#include <numeric>
#include <cassert>

/**
 * Performs Gram-Schmidt orthogonalization on a given basis.
 *
 * @param basis A vector of vectors representing the input basis.
 * @return A vector of vectors representing the orthogonalized basis.
 */
std::vector<std::vector<double>> gramSchmidt(const std::vector<std::vector<double>> &basis)
{
    size_t n = basis.size(); // Number of vectors in the basis
    size_t m = basis[0].size(); // Dimension of each vector
    std::vector<std::vector<double>> orthogonalBasis(n, std::vector<double>(m, 0.0));

    for (size_t i = 0; i < n; ++i) {
        // Start with the current vector
        orthogonalBasis[i] = basis[i];
        for (size_t j = 0; j < i; ++j) {
            // Compute the projection of basis[i] onto orthogonalBasis[j]
            double dotProduct = std::inner_product(basis[i].begin(), basis[i].end(), orthogonalBasis[j].begin(), 0.0);
            double normSquared = std::inner_product(orthogonalBasis[j].begin(), orthogonalBasis[j].end(), orthogonalBasis[j].begin(), 0.0);
            double projectionFactor = dotProduct / normSquared;
            for (size_t k = 0; k < m; ++k) {
                orthogonalBasis[i][k] -= projectionFactor * orthogonalBasis[j][k];
            }
        }
    }
    return orthogonalBasis;
}

/**
 * Implements the LLL (Lenstra-Lenstra-Lovász) algorithm for lattice basis reduction.
 *
 * @param basis A vector of vectors representing the lattice basis to be reduced.
 * @param delta A parameter (0.5 < delta <= 1.0) controlling the strength of the reduction.
 */
void lllAlgorithm(std::vector<std::vector<double>> &basis, double delta = 0.75)
{
    assert(delta > 0.5 && delta <= 1.0); // Valid range for delta

    size_t n = basis.size(); // Number of basis vectors
    size_t m = basis[0].size(); // Dimension of each vector

    while (true) {
        // Perform Gram-Schmidt orthogonalization
        auto orthogonalBasis = gramSchmidt(basis);
        bool changed = false; // Flag to track if any changes were made in this iteration

        for (size_t i = 1; i < n; ++i) {
            // Step 1: Size reduction
            for (size_t j = i - 1; j < i; --j) {
                // mu = <b[i], b*[j]> / <b*[j], b*[j]>
                double mu = std::inner_product(basis[i].begin(), basis[i].end(), orthogonalBasis[j].begin(), 0.0) / std::inner_product(orthogonalBasis[j].begin(), orthogonalBasis[j].end(), orthogonalBasis[j].begin(), 0.0);

                if (std::abs(mu) > 0.5) {
                    // Round mu to the nearest integer
                    int roundMu = std::round(mu);
                    for (size_t k = 0; k < m; ++k) {
                        basis[i][k] -= roundMu * basis[j][k];
                    }
                }
            }

            // Step 2: Check the Lovász condition

            double mu_cond = std::inner_product(basis[i].begin(), basis[i].end(), orthogonalBasis[i - 1].begin(), 0.0) / std::inner_product(orthogonalBasis[i - 1].begin(), orthogonalBasis[i - 1].end(), orthogonalBasis[i - 1].begin(), 0.0);
            double mu_cond_squared = mu_cond * mu_cond;
            double lhs = std::inner_product(orthogonalBasis[i].begin(), orthogonalBasis[i].end(), orthogonalBasis[i].begin(), 0.0);
            double rhs = (delta - mu_cond_squared) * std::inner_product(orthogonalBasis[i - 1].begin(), orthogonalBasis[i - 1].end(), orthogonalBasis[i - 1].begin(), 0.0);

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

/**
 * Utility function to print a matrix.
 *
 * @param matrix A vector of vectors representing the matrix to be printed.
 */
void printMatrix(const std::vector<std::vector<double>> &matrix)
{
    for (const auto &row : matrix) {
        for (double value : row) {
            std::cout << value << " ";
        }
        std::cout << std::endl;
    }
}

void gram_schmidt_tests()
{
    std::vector<std::vector<double>> test1 = { { 0, 3, 4 }, { 1, 0, 1 }, { 1, 1, 3 } };
    auto output = gramSchmidt(test1);
    printMatrix(output);
}

void test_lll(int d, int n)
{
    std::vector<std::vector<double>> lattice(d, std::vector<double>(n, 0.0));
    for (int i = 0; i < d; i++) {
        for (int j = 0; j < n; j++) {
            lattice[i][j] = rand() % 1000;
        }
    }

    std::cout << "Original Matrix:\n";
    printMatrix(lattice);

    std::cout << "Reduced matrix:\n";
    lllAlgorithm(lattice);
    printMatrix(lattice);
}

/**
 * Performs lll in-place on the given `lattice`.
 * `lattice` is interpreted as a 2D-array of doubles,
 * of dimensions `vector_dimension` x `num_of_vectors`
 *
 * So accessing the i-th coordinate of the j-th vector would be
 * `lattice[j * vector_dimension + i]`
 * */
extern "C" void lll(double *lattice, int num_of_vectors, int vector_dimension)
{
    std::vector<std::vector<double>> lattice_vec;
    for (int j = 0; j < num_of_vectors; j++) {
        std::vector<double> vec(lattice + (vector_dimension * j), lattice + (vector_dimension * (j + 1)));
        lattice_vec.push_back(vec);
    }

    lllAlgorithm(lattice_vec);

    for (int j = 0; j < num_of_vectors; j++) {
        for (int i = 0; i < vector_dimension; i++) {
            lattice[j * vector_dimension + i] = lattice_vec[j][i];
        }
    }
}

/**
 * Main function to demonstrate the LLL algorithm.
 *
 * @return Exit status of the program.
 */
int main()
{
    test_lll(50, 50);

    // Example basis: a set of vectors in a lattice
    std::vector<std::vector<double>> basis = {
        { 1, 2, 3, 4 },
        { 3, 1, 4, 1 },
        { 5, 9, 2, 6 },
        { 5, 3, 5, 8 }
    };

    std::cout << "Original Basis:" << std::endl;
    printMatrix(basis);

    // Perform LLL reduction
    lllAlgorithm(basis);

    std::cout << "Reduced Basis:" << std::endl;
    printMatrix(basis);

    double basis2[] = {
        1, 2, 3, 4,
        3, 1, 4, 1,
        5, 9, 2, 6,
        5, 3, 5, 8
    };

    std::cout << "With carrays:\n";
    lll(basis2, 4, 4);
    std::cout << "After lll: " << basis2[1] << "\n";

    return 0;
}
