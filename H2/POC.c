#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>     



typedef unsigned char uchar;
int longueur_de_la_clef = 16 ;
int longueur_de_la_clef_etendue = 240;

uchar *K;
uchar *vecteur;

// bloc qui sert pour le mode CBC
uchar last[16];
int Nr = 10, Nk = 4;

// clé étendue 
uchar *W;


// bloc courant à chiffrer
uchar State[16];

// table de substitution
uchar SBox[256] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};


uchar Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 } ;

  //

/*void os2ip (){
    mpz_set_ui(code, 0UL);
    for (int i = 0; i<strlen(encodage) ; i++) { // On utilise la méthode de Horner
        mpz_mul_ui(code, code, (unsigned int) 256);
        mpz_add_ui(code, code, (unsigned int) encodage[i]);
    }
}*/



////////////////////////////////chiffrage d'un  bloc aes////////////////////////////////////////////////////////
uchar gmul(uchar a, uchar b) {
  uchar p = 0;
  uchar hi_bit_set;
  int i;
  for(i = 0; i < 8; i++) {
    if((b & 1) == 1) 
      p ^= a;
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if(hi_bit_set == 0x80) 
      a ^= 0x1b;		
    b >>= 1;
  }
  return p;
}


void SubBytes(void){

      for(int i = 0; i < 16 ; i++)
        State[i] = SBox[(int)State[i]];

       
}
void ShiftRows(void){

    /*ligne 2*/
      uchar tmp = State[1];
      for(int i = 1; i < 13;i+=4)State[i] = State[i+4];
      State[13] = tmp;
    /*ligne 3*/
    tmp  = State[2];
    State[2] = State[10];
    State[10] = tmp;
    tmp = State[6];
    State[6] = State[14];
    State[14]  = tmp;

    /* ligne 4*/
    tmp = State[3];
    State[3] =  State[15];
    State[15] = State[11];
    State[11] = State[7];
    State[7] = tmp;


}
void MixColumns(void){

    uchar tabmix[16] = {0x02,0x03,0x01,0x01,0x01,0x02,0x03,0x01,0x01,0x01,0x02,0x03,0x03,0x01,0x01,0x02};
    int i =0;
    uchar b0,b1,b2,b3;

    for(i= 0; i < 16; i+=4){//colonne par colonne

       
        
       
         b0=gmul( State[i],tabmix[0])^gmul( State[i+1],tabmix[1])^gmul( State[i+2],tabmix[2])^gmul( State[i+3],tabmix[3]) ;
         b1=gmul( State[i],tabmix[4]) ^gmul( State[i+1],tabmix[5])^gmul( State[i+2],tabmix[6])^gmul( State[i+3],tabmix[7]) ;
         b2=gmul( State[i],tabmix[8]) ^gmul( State[i+1],tabmix[9])^gmul( State[i+2],tabmix[10])^gmul( State[i+3],tabmix[11]) ;
         b3=gmul( State[i],tabmix[12]) ^gmul( State[i+1],tabmix[13])^gmul( State[i+2],tabmix[14])^gmul( State[i+3],tabmix[15]) ;
       
       State[i] = b0;
       State[i+1] = b1;
       State[i+2] = b2;
       State[i+3] = b3;

    }
}
void AddRoundKey(int r){

    for(int i = 0; i < 16;i++)
      State[i] = State[i]^W[r*16+i];

}

void chiffrer(uchar *vec){
  int i;
 // faire xor avec vecteur et block à calculé
for( i = 0 ; i < 16; i++ )
  State[i] = State[i]^vec[i]; 
 AddRoundKey(0);
 for (i = 1; i < Nr; i++) {
    SubBytes();
    ShiftRows();
    MixColumns();
    AddRoundKey(i);
  }
  SubBytes();
  ShiftRows();
  AddRoundKey(Nr);
}
/////////////////////////////////fin de chiffrage de bloc/////////////////////////////////////////////////////////

uchar* bourragePKCS5(uchar*tab,int k,int taille_tab,int rempli){

    int chiffre_a_bourrer = k - (rempli%k);

    if(rempli + chiffre_a_bourrer > taille_tab){
      printf("problème bourrage PKCS5 avec taille_tab ( trop petit)");
      exit(1);
    }

    for(int i = rempli; i < rempli + chiffre_a_bourrer;i++){

          tab[i] = (uchar)chiffre_a_bourrer;
    }

    return tab;
}



void calcule_la_clef_courte(char * clef_secrete, int taille_cle){
 
  
 
    
  int k_index = 0;
  for(int i = 0; i < taille_cle; i = i+2){
   
    char hexa[2];
    hexa[0] = clef_secrete[i];
    hexa[1] = clef_secrete[i+1];


    int entier = 0;
    sscanf(hexa,"%02x",&entier);// convertit deux caractère hexadecimal en 1 décimal
   
    K[k_index] =(uchar)entier;
    k_index++;
  }
}


void affiche_la_clef(uchar *clef, int longueur,int option)// option: 0 affiche comme clef secrete; 1 affiche sous forme donné en commentaire en bas
{

   printf("\n");
  if(option == 0)
  for (int i=0; i<longueur; i++) { printf ("%2x ", clef[i]); }
 

  if(option == 1){
    printf("\n ronde 0  ::");
    for (int i=0; i< longueur; i++){
        
             printf ("%02x ", clef[i]);

             if((i+1)%16 == 0 && i != 0 && i != longueur-1)printf("\n ronde %d  ::",(i/16)+1);
        
    }

  }
   printf("\n");
}
/////////////////////extension clé courte/////////////////////

uchar * RotWord(uchar tmp[4]){

  uchar transfert = tmp[0];

  for(int i = 0;i <4;i++)
    tmp[i] = tmp[i+1];

  tmp[3] = transfert;

  return tmp;
}


uchar * SubWord(uchar tmp[4]){

  for(int i = 0 ; i < 4; i++)
      tmp[i] = SBox[(int)tmp[i]];

  return tmp;
}


void calcule_la_clef_etendue()
{
  if (longueur_de_la_clef == 16){
    Nr = 10; Nk = 4;
  } else if (longueur_de_la_clef == 24){
    Nr = 12; Nk = 6;
  } else {
    Nr = 14; Nk = 8; }
  longueur_de_la_clef_etendue = 4*(4*(Nr+1));

  for(int i=0; i<longueur_de_la_clef_etendue; i++) W[i] = 0;

  for(int i=0; i < longueur_de_la_clef; i++)W[i] = K[i];

  for(int nb_ronde = Nk*4; nb_ronde < longueur_de_la_clef_etendue; nb_ronde =nb_ronde+4){

       uchar *tmp = malloc( 4*sizeof(uchar));

      for(int index = 0; index < 4; index++){
          tmp[index] = W[nb_ronde-4+index];
      }

      if((nb_ronde/4)% Nk == 0){
          tmp = RotWord(tmp);
          tmp = SubWord(tmp);
          
          tmp[0] = tmp[0]^Rcon[(nb_ronde/(Nk*4))-1];
          for(int i = 1; i < 4;i++)tmp[i] = tmp[i]^0;

      }
      else 
          if(Nk > 6 && (nb_ronde%Nk)== 4){
              tmp = SubWord(tmp);
          }
      
      for(int i = 0; i < 4; i++)tmp[i] =W[nb_ronde - (4*Nk )+i]^tmp[i];

      for(int i = 0; i < 4; i++)W[nb_ronde + i] = tmp[i];
  }
 
  
}

////////////////fin extension clé courte/////////////////////

int main(int argc,char **argv){

    if(argc != 4){
      printf("Usage : ./executable  fichier_destination   fichier_cle_courte_aes fichier_a_crypter\n  ");
      exit(1);
    }
    srand(time(NULL));
    //allocation
    K = malloc(longueur_de_la_clef*sizeof(uchar));
    vecteur = malloc(16*sizeof(uchar));
    W = malloc(longueur_de_la_clef_etendue*sizeof(uchar));

    char tmp_key[longueur_de_la_clef*2];

    //recupération de la clé
    FILE *fichier_key = NULL;

    fichier_key = fopen(argv[2],"r");

    if(fichier_key == NULL){
      printf("fichier de la clé pas reussi a ouvrir %s\n",argv[2]);
      exit(1);
    }
    char alpha;
    int index = 0;
    
  while( (alpha = fgetc(fichier_key)) != EOF){
     if(index >= longueur_de_la_clef*2){
              printf("erreur clé du fichier trop longue");
              exit(1);
            }
     tmp_key[index] = alpha;
     index++;
  }
  
  fclose(fichier_key);

    printf("key : %s\n",tmp_key);
    calcule_la_clef_courte(tmp_key,longueur_de_la_clef*2); 

    // faire un vecteur aléatoire   

    printf("la clé coutre K: \n");
     for(int i = 0; i < longueur_de_la_clef;i++)
           printf("%02x ",K[i]);

    printf("\n\n");

      for(int i = 0; i < 16; i++)
        vecteur[i] = rand()%255;
    printf("le vecteur: \n");
       for(int i = 0; i < longueur_de_la_clef;i++)
              printf("%02x ",vecteur[i]);
     printf("\n\n");
    
   

    FILE *fichier_ecrire = NULL;
    fichier_ecrire  = fopen(argv[1],"a+");

    if(fichier_ecrire ==NULL ){
      printf("pas reussi à ouvrir");
      exit(1);
    }
    for(int i = 0; i < longueur_de_la_clef;i++){
        fwrite(&vecteur[i],sizeof(uchar),1,fichier_ecrire);
    }
    
   
   
   
    

    calcule_la_clef_etendue();
   // affiche_la_clef(W, longueur_de_la_clef_etendue,1); 

     //prendre la taille du fichier à crypter pour allouer la mémoire

    long int taille;
    FILE *fichier_decryp = NULL;

    fichier_decryp = fopen(argv[3],"r");

    if(fichier_decryp == NULL){
      printf("probleme fichier à crypter\n");
      exit(1);
    }

     fseek (fichier_decryp, 0, SEEK_END);   
    taille =ftell (fichier_decryp);
    fseek (fichier_decryp, 0, 0);
    printf("taille fichier %ld\n",taille);

    uchar *fichier;
    fichier = malloc((taille+16) * sizeof(uchar));

    long int index_f = 0;
    int trad;

    while(( trad =fgetc(fichier_decryp)) != EOF ){

        if(trad < 0 || trad > 255){
            printf("probleme de valeur trad %d",trad);
            exit(1);

        }
          
          fichier[index_f] = (uchar)trad;
         index_f++;
    }

    fclose(fichier_decryp);

    fichier = bourragePKCS5(fichier,16,taille+16,index_f);
    taille += 16 - ((index_f)%16);

    
    
    // chiffrement du fichier
   int nb_block = taille/16;
   uchar block_CBC[16];
  for(int i = 0; i < nb_block; i++)
  {
    if(i == 0){
        for(int i_v = 0; i_v < 16; i_v++)
          block_CBC[i_v] = vecteur[i_v];
    }
      //remplissage du block 
      for(int j = 0 ; j < 16 ; j++)
          State[j] = fichier[i*16 + j];
      chiffrer(block_CBC);

       for(int i_v = 0; i_v < 16; i_v++)
          block_CBC[i_v]= State[i_v];

      //ecrit le block dans le fichier
      fwrite(State,sizeof(uchar),16,fichier_ecrire);
  }
  
   
   fclose(fichier_ecrire);
   

    return 0;
}