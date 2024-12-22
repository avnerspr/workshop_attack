# Large Prime Generation for RSA
import random

# Pre generated primes
primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
					31, 37, 41, 43, 47, 53, 59, 61, 67,
					71, 73, 79, 83, 89, 97, 101, 103,
					107, 109, 113, 127, 131, 137, 139,
					149, 151, 157, 163, 167, 173, 179,
					181, 191, 193, 197, 199, 211, 223,
					227, 229, 233, 239, 241, 251, 257,
					263, 269, 271, 277, 281, 283, 293,
					307, 311, 313, 317, 331, 337, 347, 349]


def n_bit_random(n):
	'''Returns a random n bit integer'''
	
	return random.randrange(2**(n-1)+1, 2**n - 1)


def get_low_probability_prime(n):
	'''Generate a prime candidate divisible 
	by first primes'''
	
	while True:
		pc = n_bit_random(n)

		for divisor in primes_list:
			if pc % divisor == 0 and divisor ** 2 <= pc:
				break
		else:
			return pc


def miller_rabin_test(potential_prime):
	'''Run 20 iterations of Rabin Miller Primality test'''
	
	max_divisions_by_two = 0
	ec = potential_prime - 1
	
	while ec % 2 == 0:
		ec >>= 1
		max_divisions_by_two += 1
		
	assert(2**max_divisions_by_two * ec == potential_prime-1)

	def trial_composite(round_tester):
		if pow(round_tester, ec, potential_prime) == 1:
			return False
		for i in range(max_divisions_by_two):
			if pow(round_tester, 2**i * ec, potential_prime) == potential_prime-1:
				return False
		return True

	# Set number of trials here
	number_of_rabin_trials = 20
	for i in range(number_of_rabin_trials):
		round_tester = random.randrange(2, potential_prime)
		if trial_composite(round_tester):
			return False
	return True


def get_n_bit_high_prob_prime(n : int):
	while True:
		prime_candidate = get_low_probability_prime(n)
		if not miller_rabin_test(prime_candidate):
			continue
		else:
			return prime_candidate

