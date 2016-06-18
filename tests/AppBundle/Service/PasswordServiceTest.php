<?php
namespace Tests\AppBundle\Service;

use AppBundle\Service\PasswordService;

class PasswordServiceTest extends \PHPUnit_Framework_TestCase
{
    public function testSavePassword()
    {
        $service = new PasswordService($this->createDoctrine(function ($em) {
            $em->expects($this->once())->method('persist');
            $em->expects($this->once())->method('flush');
        }));
        $encoder = $this->createMock('Symfony\\Component\\Security\\Core\\Encoder\\PasswordEncoderInterface');
        $encoder->expects($this->once())->method('encodePassword')->with('qweqwe')->will($this->returnValue('encoded'));
        $encoderFactory = $this->createMock('Symfony\\Component\\Security\\Core\\Encoder\\EncoderFactoryInterface');
        $encoderFactory->expects($this->once())->method('getEncoder')->will($this->returnValue($encoder));
        $user = $this->createMock('AppBundle\\Entity\\User');
        $user->expects($this->once())->method('setPassword')->with('encoded');
        $user->expects($this->once())->method('setConfirmationHash')->with(null);

        $service->savePassword('qweqwe', $encoderFactory, $user);
    }

    public function testGenerateWithoutConflicts()
    {
        $service = new PasswordService($this->createDoctrine(function ($em) {
            $repo = $this->createMock('Doctrine\\ORM\\EntityRepository');
            $repo->expects($this->once())->method('findBy')->will($this->returnValue(null));
            $em->expects($this->once())->method('getRepository')->will($this->returnValue($repo));
            $em->expects($this->once())->method('transactional')->will($this->returnCallback(function ($callback) {
                $callback();
            }));
        }));
        $user = $this->createMock('AppBundle\\Entity\\User');
        $service->generateConfirmationHash($user);
    }

    public function testGenerateWith1Conflict()
    {
        $service = new PasswordService($this->createDoctrine(function ($em) {
            $repo = $this->createMock('Doctrine\\ORM\\EntityRepository');
            $repo->expects($this->exactly(2))->method('findBy')
                ->withConsecutive([['confirmation_hash' => 'aaa']], [['confirmation_hash' => 'bbb']])
                ->will($this->onConsecutiveCalls([1], []));
            $em->expects($this->any())->method('getRepository')->will($this->returnValue($repo));
            $em->expects($this->once())->method('transactional')->will($this->returnCallback(function ($callback) {
                $callback();
            }));
        }));
        $user = $this->createMock('AppBundle\\Entity\\User');
        $generator = $this->getMockBuilder('stdClass')->setMethods(['generate'])->getMock();
        $generator->expects($this->exactly(2))->method('generate')->will($this->onConsecutiveCalls('aaa', 'bbb'));
        $this->assertEquals('bbb', $service->generateConfirmationHash($user, [$generator, 'generate']));
    }

    public function testCreateUser()
    {
        $service = new PasswordService($this->createDoctrine(function () {}));
        $user = $service->createUser('test@domain');
        $this->assertEquals('test@domain', $user->getUsername());
        $this->assertEquals('test@domain', $user->getEmail());
        $this->assertNotEmpty($user->getPassword());
    }

    /**
     * @param $setUpEm
     * @return \Doctrine\Bundle\DoctrineBundle\Registry
     */
    private function createDoctrine($setUpEm)
    {
        $em = $this->createMock('Doctrine\\ORM\\EntityManager');
        $setUpEm($em);
        $registry = $this->createMock('Doctrine\\Bundle\\DoctrineBundle\\Registry');
        $registry->expects($this->once())->method('getManager')->will($this->returnValue($em));
        return $registry;
    }
}
