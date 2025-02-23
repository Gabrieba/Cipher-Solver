#include <stdio.h>
#include <stdlib.h>
#include "string.h"

#define COLOR_RESET			"\x1b[0m"
#define COLOR_RED				"\x1b[31m"
#define COLOR_YELLOW		"\x1b[33m"
#define STYLE_BOLD			"\x1b[1m"

#define ASCII_TABLE_SIZE	96
#define MAX_TEXT_SIZE			256

// Display "msg" in the bash in bold style and red color
// Return nothing
void DisplayError(char* msg){
	printf("" STYLE_BOLD COLOR_RED);
	printf("%s", msg);
	printf(COLOR_RESET "\n");
	return;
}

// Display "msg" in the bash in bold style and yellow color
// Return nothing
void DisplayWarning(char* msg){
	printf("" STYLE_BOLD COLOR_YELLOW);
	printf("%s", msg);
	printf(COLOR_RESET "\n");
	return;
}

// Reverse the order of the caracters of the two keys
// Return nothing
void ReverseKeys(char* key1, char* key2){
	puts("TODO");
	return;
}

// Encrypt the text 'plainpair' by using the two keys and the IV
// Compute the IB and update the two new keys
// The encrypted text is stored in IV
// Return nothing
void Encryption(char* plainpair, char* key1, char* key2, char* ib, char* iv){
	int i=0; int j=0; int k=0; int l=0;
	int index1, index2;
	char char_tmp;
// Determine the position of the first caracter of the plainpair and the first caracter of IV, sum the two
// numbers to find the first caracter of IB in key1
	while (plainpair[0] != key1[i])
		i++;
	while (iv[0] != key1[j])
		j++;
	index1 = (i+j+1)%95;
	ib[0] = key1[index1];

// Determine the position of the second caracter of the plainpair and the second caracter of IV, sum the two
// numbers to find the second caracter of IB in key1
	i = 0;
	j = 0;
	while (plainpair[1] != key1[i])
		i++;
	while (iv[1] != key1[j])
		j++;
	index2 = (i+j+1)%95;
	ib[1] = key1[index2];

// Determine the first encrypted caracter (IV[0]) with the distance between the two caracters of IB
// in key2
	if (index2 > index1)
		iv[0] = key2[index2-index1-1];
	else																// wrapping around the key
		iv[0] = key2[index2+95-index1-1];

// Determine the second encrypted caracter (IV[1]) with the distance between the first encrypted caracter
// (IV[0]) and the first caracter of IB in key2
	i = 0;
	j = 0;
	while (iv[0] != key2[i])
		i++;
	while (ib[0] != key2[j])
		j++;
	if (j > i)
		iv[1] = key1[j-i-1];
	else																// wrapping around the key
		iv[1] = key1[j+95-i-1];

// Swap the position of the two IB caracters in key1 if the two caracters of IB are different
	if (ib[0] != ib[1]){
		char_tmp = key1[index1];
		key1[index1] = key1[index2];
		key1[index2] = char_tmp;
	}

// Swap the position of the two IV caracters in key2 if the two ciphertext caracters are different
	if (iv[0] != iv[1]){
		while (iv[0] != key2[k])
			k++;
		while (iv[1] != key2[l])
			l++;
		char_tmp = key2[k];
		key2[k] = key2[l];
		key2[l] = char_tmp;
	}

// Reverse the order of the two keys if the first distance (used to get the first ciphertext caracter) is odd
	if (((index2 > index1)&&((index2-index1)%2 == 1))||((index2 < index1)&&((index2+95-index1)%2 == 1)))
		ReverseKeys(key1, key2);

// Shift all the caracters of the two keys by the value of the second distance (used to get the second
// ciphertext caracter)
	if (j > i){
		puts("TODO");
	}
	return;
}


// Encrypt message from 'plaintext' into 'ciphertext' using the lady-liz cipher, the keys 'key1' and 'key2'
// and the IV 'iv'
// Return nothing
void EncryptMessage(char* plaintext, char* ciphertext, char* key1, char* key2, char* iv){
	char ib[2];
	int k;
	int len_plaintext = strlen(plaintext);
	Encryption(plaintext, key1, key2, ib, iv);
	strcat(ciphertext, iv);
	printf("final = %s\n", ciphertext);
//	for (k=0; k < len_plaintext; k+=2){
//		Encryption((plaintext+2*k), key1, key2, ib, iv);
//	}
	return;
}


// Check if there is non printable ASCII caracter in 'msg' text
// Return 0 if all caracters are printable, 1 otherwise
int IsPrintableASCII(char* msg){
	int len_msg = strlen(msg);
	int i;
	for (i=0; i<len_msg; i++){
		if ((msg[i] < ' ' || msg[i] > '~') && msg[i] != 10){		// If c is not a printable ASCII caracter and not a line break
			DisplayWarning("File contains at least one non-printable ASCII caracter.");
			return 1;
		}
	}
	return 0;
}

// Check if the key is in the correct format (i.e. made of a permutation of all printable ASCII caracters)
// Return 0 if yes, 1 otherwise
int CheckKey(char* key){
	int i,j;
	int tab[ASCII_TABLE_SIZE];
	if(strlen(key) > ASCII_TABLE_SIZE){
		DisplayWarning("One of the key is not in the correct format: too much caracters.");
		return 1;
	}
	if(strlen(key) < ASCII_TABLE_SIZE){
		DisplayWarning("One of the key is not in the correct format: not enough caracters.");
		return 1;
	}
	tab[0] = key[0];
	for (i=1; i<ASCII_TABLE_SIZE; i++){
		for (j=0; j<i; j++){
			if (key[i] == key[j]){
				DisplayWarning("One of the key is not in the correct format: at least one caracter is present twice.");
				return 1;
			}
		}
		tab[i] = key[i];
	}
	return 0;
}


// MAIN PROGRAM: arguments handler + errors handler + tasks handler
// Return nothing
void main(int argc, char* argv[]){
	FILE* fkey1p;
	FILE* fkey2p;
	FILE* ftextp;
	char textsource[MAX_TEXT_SIZE];
	char key1[ASCII_TABLE_SIZE+2];
	char key2[ASCII_TABLE_SIZE+2];

//========================================================================
// ARGUMENTS HANDLER
	if (argc == 2){
		if (strcmp(argv[1], "-help") == 0){			// If user asks for help
			puts("==== HELP ====");
			puts("TO ENCRYPT:");
			puts("./solver -e 'plaintext.txt' 'IV' 'key1.txt' 'key2.txt'");
			puts("");
			puts("TO DECRYPT:");
			puts("./solver -d 'cyphertext.txt' 'IV' 'key1.txt' 'key2.txt'");
			puts("");
			puts("TO GET HELP:");
			puts("./solver -help");
			puts("");
			exit(EXIT_SUCCESS);
		}
		else{
			DisplayWarning("Wrong argument. Use /solver -help for help.");
			exit(EXIT_FAILURE);
		}
	}
	if (argc > 6){
		DisplayWarning("Too much arguments. Use /solver -help for help.");
		exit(EXIT_FAILURE);
	}
	if (argc < 6){
		DisplayWarning("Not enough arguments. Use /solver -help for help.");
		exit(EXIT_FAILURE);
	}
	if (strlen(argv[3]) != 2){		// 'IV' argument
		DisplayWarning("Intermediate Vector must contain 2 caracters exactly.");
		exit(EXIT_FAILURE);
	}
	if (strcmp(argv[1],"-e") != 0 && strcmp(argv[1],"-d") != 0){		// '-e' or '-d' argument
		DisplayWarning("Wrong argument. Use /solver -help for help.");
		exit(EXIT_FAILURE);
	}

//========================================================================
// DATA RECOVERY
	fkey1p = fopen(argv[4],"r");
	if (fkey1p == NULL){
		DisplayError("Cannot open file.");
		exit(EXIT_FAILURE);
	}
	fgets(key1, ASCII_TABLE_SIZE+2, fkey1p);
	fclose(fkey1p);

	fkey2p = fopen(argv[5],"r");
	if (fkey2p == NULL){
		DisplayError("Cannot open file.");
		exit(EXIT_FAILURE);
	}
	fgets(key2, ASCII_TABLE_SIZE+2, fkey2p);
	fclose(fkey2p);

	ftextp = fopen(argv[2],"r");
	if (ftextp == NULL){
		DisplayError("Cannot open file.");
		exit(EXIT_FAILURE);
	}
	fgets(textsource, MAX_TEXT_SIZE, ftextp);
	fclose(ftextp);

	char* textdst = calloc(MAX_TEXT_SIZE, sizeof(char));		// plaintext or cyphertext
	if (textdst == NULL){
		DisplayError("Cannot allocate memory for plaintext / cyphertext.");
		exit(EXIT_FAILURE);
	}
//================================================================
// DATA VALIDITY CHECKING
	if (IsPrintableASCII(key1) || CheckKey(key1) ||
			IsPrintableASCII(key2) || CheckKey(key2) ||
			IsPrintableASCII(textsource) || IsPrintableASCII(argv[3])){
		free(textdst);
		exit(EXIT_FAILURE);
	}

//================================================================
// TASK HANDLER
	EncryptMessage(textsource, textdst, key1, key2, argv[3]);

	free(textdst);
	exit(EXIT_SUCCESS);
}
