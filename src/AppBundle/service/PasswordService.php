<?php
namespace AppBundle\Service;

use AppBundle\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Registry;
use Doctrine\ORM\EntityManager;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;

class PasswordService
{
    /**
     * @var EntityManager
     */
    private $em;

    public function __construct(Registry $doctrine)
    {
        $this->em = $doctrine->getManager();
    }

    public function savePassword($password, EncoderFactoryInterface $encoder, User $user)
    {
        $user->setPassword($encoder->getEncoder($user)->encodePassword($password, null));
        $this->em->persist($user);
        $this->em->flush();
    }

    public function generateConfirmationHash(User $user)
    {
        $user->setConfirmationHash(uniqid());
        $this->em->persist($user);
        $this->em->flush();
        return $user->getConfirmationHash();
    }

    public function findUserByConfirmationHash($hash)
    {
        $users = $this->em->getRepository('AppBundle:User')->findBy(['confirmation_hash' => $hash]);
        return $users ? $users[0] : null;
    }

    public function findUserByEmail($email)
    {
        $users = $this->em->getRepository('AppBundle:User')->findBy(['email' => $email]);
        return $users ? $users[0] : null;
    }
}
